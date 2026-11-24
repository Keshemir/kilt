#!/usr/bin/python3 -I
"""kilt — кто может зайти на сервер по SSH и что ему там можно.

  kilt            меню (от root): стрелки ↑↓, Enter, Esc — назад/выход
  kilt setup      установить или обновить окружение (sshd, sudo, таймер, фаервол); можно повторять
  kilt sync       пересчитать права на файлы, ключи и сеть (таймер, раз в 10 минут)
  kilt boot       сетевые запреты и виды проектов при загрузке сервера (служба, до sshd)
  kilt firewall   только сетевые правила
  kilt ps | logs | restart | stop | start | exec …
                  контейнеры проекта; у личной учётки это тот же kilt через sudo (kilt help)

Два вида доступа:
  весь сервер, root — ключ в /root/.ssh/authorized_keys          → ssh root@сервер
  личная учётка     — свой пользователь Linux (группа kilt)    → ssh логин@сервер
      без проектов: только осмотреться на сервере;
      по каждому проекту «чтение» (группа p-<проект>) или «root на проект» (ещё и p-<проект>-rw);
      файлы проекта — в ~/<проект>, контейнеры — командой kilt (kilt ps, kilt logs …).

Скрипт работает от root и не доверяет ничему, что может менять обычный пользователь:
запускается в изолированном режиме Python (-I), права на файлы ставит по открытым
дескрипторам (без гонок с символическими ссылками), сеть режет по номеру пользователя.
"""
import base64, datetime, errno, fcntl, fnmatch, grp, hashlib, ipaddress, json, os, pwd, re, resource
import secrets, shutil, signal, stat, struct, subprocess, sys, tempfile, termios, time


# ---------------------------------------------------------------- язык интерфейса
def _ui_language():
    try:
        with open("/etc/kilt/config.json") as f:
            v = json.load(f).get("language")
        if v in ("en", "ru"):
            return v
    except (OSError, ValueError, AttributeError):
        pass
    env = os.environ.get("LC_ALL") or os.environ.get("LC_MESSAGES") or os.environ.get("LANG") or ""
    return "ru" if env.lower().startswith("ru") else "en"


UI_LANG = _ui_language()


def _(s):
    return EN.get(s, s) if UI_LANG == "en" else s


EN = {
    __doc__: """kilt — who can log in to this server over SSH, and what they can do there.

  kilt            menu (run as root): arrows ↑↓, Enter, Esc — back / exit
  kilt setup      install or update kilt (sshd, sudo, timer, firewall); you can run it again
  kilt sync       update file permissions, keys and network rules (runs every 10 minutes)
  kilt boot       network rules and project folders when the server starts (before sshd)
  kilt firewall   network rules only
  kilt ps | logs | restart | stop | start | exec …
                  project containers; personal accounts use these commands too (through sudo), see kilt help

Two kinds of access:
  whole server, root — key in /root/.ssh/authorized_keys     → ssh root@server
  personal account   — own Linux user (group kilt)            → ssh login@server
      no projects: can only look around the server;
      for each project: "read" or "root on project";
      project files are in ~/<project>, containers: kilt ps, kilt logs …

kilt runs as root and does not trust anything that a normal user can change.
""",
    "\nТвои проекты: ": "\nYour projects: ",
    " — установи: {0}": " — install: {0}",
    ", закрыто открытых сессий: {0}": ", open sessions closed: {0}",
    "Docker Engine и docker compose v2": "Docker Engine and docker compose v2",
    "Enter — назад": "Enter — back",
    "RSA-ключ слишком короткий ({0} бит). Нужен ed25519 или RSA от 2048 бит.":
        "This RSA key is too short ({0} bits). Use ed25519, or RSA with 2048 bits or more.",
    '[ -f ~/.bashrc ] && . ~/.bashrc\n'
    'echo; echo "Твои проекты: $(for f in ~/*; do case "$(readlink "$f")" in (/run/kilt/view/*) '
    'printf "%s " "$(basename "$f")";; esac; done)"\n'
    'echo "Контейнеры проекта: cd ~/<проект>, затем kilt ps, kilt logs -f <сервис>, kilt help"; echo\n':
        '[ -f ~/.bashrc ] && . ~/.bashrc\n'
        'echo; echo "Your projects: $(for f in ~/*; do case "$(readlink "$f")" in (/run/kilt/view/*) '
        'printf "%s " "$(basename "$f")";; esac; done)"\n'
        'echo "Project containers: cd ~/<project>, then kilt ps, kilt logs -f <service>, kilt help"; echo\n',
    "boot: вид проекта {0}: {1}": "boot: project folder {0}: {1}",
    "boot: фаервол: {0}": "boot: firewall: {0}",
    "контейнеры: вид проекта {0}: {1}": "containers: project folder {0}: {1}",
    "контейнеры: обновление правил не удалось: {0}": "containers: could not update the rules: {0}",
    "группа {0} — то же, что root": "{0} group — same as root",
    "kilt exec <сервис> [команда…]": "kilt exec <service> [command…]",
    "kilt -p <проект> <команда> …": "kilt -p <project> <command> …",
    "kilt — контейнеры твоего проекта. Проект берётся из папки, где ты стоишь (cd ~/shop), или kilt -p <проект> …\n\n"
    "  kilt ps                         какие контейнеры и в каком состоянии\n"
    "  kilt logs [флаги] [сервис…]     журнал контейнеров; флаги: -f, -t, --tail N, --since, --until\n"
    "  kilt restart|stop|start сервис… только с правами «root на проект»\n"
    "  kilt exec сервис [команда…]     зайти в контейнер (по умолчанию sh), только «root на проект»\n":
        "kilt — the containers of your project. kilt finds the project from the folder you are in (cd ~/shop), "
        "or use kilt -p <project> …\n\n"
        "  kilt ps                         list the containers and their state\n"
        "  kilt logs [flags] [service…]    container logs; flags: -f, -t, --tail N, --since, --until\n"
        "  kilt restart|stop|start service… only with \"root on project\"\n"
        "  kilt exec service [command…]    open a shell in a container (sh by default), only with \"root on project\"\n",
    "kilt: меню kilt запускается от root (ssh root@сервер, затем kilt). Команды контейнеров есть только у личных учёток kilt.":
        "kilt: the kilt menu works only as root (ssh root@server, then kilt). "
        "Container commands are only for kilt personal accounts.",
    "kilt: непонятно, кто вызывает": "kilt: cannot find out who is running this",
    "kilt: окружение установлено": "kilt: installed",
    "Внимание: systemd на этом сервере собран без BPF, поэтому запрет слушать порты не работает. "
    "Личные учётки смогут открыть порт выше 1024.":
        "Warning: systemd on this server is built without BPF, so the ban on listening ports does not work. "
        "Personal accounts can open ports above 1024.",
    "kilt: создан {0} — проверь адрес сервера и папки с проектами":
        "kilt: created {0} — check the server address and the project folders",
    "root на проект": "root on project",
    "root: ещё ключей не через это меню: {0} (с опциями или сертификаты)":
        "root: other keys not managed by this menu: {0} (keys with options, or certificates)",
    "ssh-keygen не признал эту строку ключом.": "ssh-keygen says this line is not a key.",
    "sshd не принял новый блок настроек — возвращён прежний файл: {0}":
        "sshd did not accept the new settings — the old file is back: {0}",
    "{0:<23} весь сервер, root   {1}…": "{0:<23} whole server, root   {1}…",
    "{0} (весь сервер, root)": "{0} (whole server, root)",
    "{0} (личная учётка)": "{0} (personal account)",
    "{0} Дать {1} root на {2}?": "{0} Give {1} root on {2}?",
    "{0} Чтобы подтвердить, введи {1}: ": "{0} To confirm, type {1}: ",
    "{0} получит ПОЛНЫЙ root на сервере (ключ {1}…).": "{0} will get FULL root on the server (key {1}…).",
    "{0} — весь сервер, root   ({1}…)": "{0} — whole server, root   ({1}…)",
    "{0} — проекты (Enter — изменить)   ключ {1}…": "{0} — projects (Enter — change)   key {1}…",
    "{0} → {1}: какой доступ?": "{0} → {1}: which access?",
    "{0}: closed — непустой список папок": "{0}: closed — must be a list of folders, not empty",
    "{0}: host — имя или адрес сервера": "{0}: host — must be the server name or address",
    "{0}: service_keys — список комментариев ключей": "{0}: service_keys — must be a list of key comments",
    "{0}: {1} нельзя закрывать целиком — там система или домашние папки людей":
        "{0}: {1} cannot be closed completely — the system or people's home folders are there",
    "{0}: {1} — нужна существующая папка с полным путём": "{0}: {1} — must be a folder that exists, with a full path",
    "{0}: в {1} лежит домашняя папка {2}": "{0}: the home folder of {2} is inside {1}",
    "{0}: владелец должен быть root, запись — только для root": "{0}: the owner must be root, and only root may write to it",
    "{0}: на пути символическая ссылка — root туда не пишет": "{0}: there is a symbolic link in the path — root will not write there",
    "{0}: не JSON ({1})": "{0}: this is not valid JSON ({1})",
    "{0}: не открывается ({1}) — нужен обычный файл, не ссылка":
        "{0}: cannot open it ({1}) — it must be a normal file, not a link",
    "{0}: недопустимый путь": "{0}: bad path",
    "{0}: новый ключ {1}": "{0}: new key {1}",
    "{0}: ожидается объект {{...}}": "{0}: must be an object {{...}}",
    "{0}: проект {1} → {2}": "{0}: project {1} → {2}",
    "{0}: проект {1} — ожидается объект с полями compose (строка), dir (строка), hide (список строк), "
    "files (только \"ro\")":
        "{0}: project {1} — must be an object with the fields compose (text), dir (text), hide (list of texts), "
        "files (only \"ro\")",
    "{0}: адресов для проброса портов больше 300 ({1}) — проброс портов выключен":
        "{0}: more than 300 port forwarding targets ({1}), so port forwarding is off",
    "{0}: это не личная учётка kilt, kilt не трогает её процессы":
        "{0}: this is not a kilt personal account, kilt does not touch its processes",
    "{0}: удалён": "{0}: deleted",
    "«root на проект» — это полное доверие: человек меняет файлы проекта и заходит в его контейнеры, "
    "а оттуда при желании и умении может получить root на всём сервере.":
        "\"Root on project\" means full trust: the person can change the project files and go into its containers. "
        "From there, a skilled person can get root on the whole server.",
    "{0}: отдельная учётка, {1}, ключей {2}": "{0}: separate account, {1}, keys: {2}",
    "ВНИМАНИЕ: не удалось завершить все процессы {0}": "WARNING: could not stop all processes of {0}",
    "ВНИМАНИЕ: проект {0}: общая с контейнером папка {1} вне защищённых каталогов, без nosuid или nodev — "
    "человек с «root на проект» может через неё получить root на сервере":
        "WARNING: project {0}: folder {1} is shared with a container, is outside the protected folders "
        "and has no nosuid or nodev — a person with \"root on project\" can get root on the server through it",
    "ВНИМАНИЕ: проект {0}: контейнер {1} получил сокет Docker — "
    "человек с «root на проект» может через него получить root на сервере":
        "WARNING: project {0}: container {1} has the Docker socket — "
        "a person with \"root on project\" can get root on the server through it",
    "ВНИМАНИЕ: проект {0}: контейнер {1} запущен с privileged — "
    "человек с «root на проект» может через него получить root на сервере":
        "WARNING: project {0}: container {1} runs with privileged — "
        "a person with \"root on project\" can get root on the server through it",
    "Вернуться": "Go back",
    "Выйти": "Exit",
    "Выйти без сохранения?": "Exit without saving?",
    "Выход": "Exit",
    "Дать": "Give",
    "Доступ к серверу {0}": "Access to server {0}",
    "Его проекты — в домашней папке: cd ~/": "Their projects are in their home folder: cd ~/",
    "Если расстались не по-хорошему — проверь сервер или переустанови его.":
        "If you did not part on good terms, check the server or reinstall it.",
    "Забрать": "Remove",
    "Забрать у {0} доступ к серверу?": "Remove server access for {0}?",
    "Имя {0} занято группой на сервере": "The name {0} is already used by a group on the server",
    "Имя {0} уже есть у другого ключа root": "The name {0} is already used by another root key",
    "Имя: ": "Name: ",
    "Ключ повреждён: скопирован не целиком или с лишними символами.":
        "The key is broken: it was copied only in part, or with extra characters.",
    "Команда {0} доступна только с правами «root на проект». У тебя: {1}.":
        "The command {0} works only with \"root on project\". You have: {1}.",
    "Контейнеры: kilt ps, kilt logs -f <сервис>": "Containers: kilt ps, kilt logs -f <service>",
    "Логин: ": "Login: ",
    "Логин: от 2 до 31 символа, латиница в нижнем регистре, цифры, - и _, начинается с буквы; "
    "нельзя начинать с p-; служебные имена нельзя":
        "Login: 2 to 31 characters, small Latin letters, numbers, - and _, starting with a letter; "
        "it cannot start with p-; system names are not allowed",
    "Настраиваю…": "Setting up…",
    "Не подтверждено — ничего не изменено.": "Not confirmed — nothing was changed.",
    "Непонятно, какой проект: зайди в его папку (cd ~/<проект>) или укажи kilt -p <проект> …":
        "Which project? Go to its folder (cd ~/<project>) or use kilt -p <project> …",
    "Неизвестная команда {0}. kilt help — список.": "Unknown command {0}. Type kilt help to see the list.",
    "Нет сервиса {0}. Есть: {1}": "No service {0}. Services: {1}",
    "Нужен gum: apt install gum": "You need gum: apt install gum",
    "Отмена": "Cancel",
    "Ошибка: {0}": "Error: {0}",
    "Ошибка: нет прав — {0}": "Error: no permission — {0}",
    "Пользователь {0} на сервере уже есть": "User {0} already exists on the server",
    "Публичный ключ: ": "Public key: ",
    "Проектов пока нет: kilt ищет проекты docker compose в папках {0}":
        "No projects yet: kilt looks for docker compose projects in {0}",
    "Пусть заходит так:": "They log in like this:",
    "У него был root: он мог оставить себе другой вход (запасной ключ, задание cron, свою программу).":
        "They had root, so they could leave another way in (a spare key, a cron job, their own program).",
    "У проекта {0} нет контейнеров.": "Project {0} has no containers.",
    "У тебя нет доступа к проекту {0}": "You have no access to project {0}",
    "Удалить": "Delete",
    "Удалить {0} с сервера вместе с домашней папкой?": "Delete {0} from the server, with their home folder?",
    "Укажи сервис: kilt {0} <сервис>. Есть: {1}": "Name a service: kilt {0} <service>. Services: {1}",
    "Учётки {0} на сервере уже нет": "The account {0} is not on the server any more",
    "Флаг {0} не поддерживается": "Flag {0} is not supported",
    "Флаги здесь не поддерживаются": "Flags are not supported here",
    "Что дать?": "What access?",
    "Это ПРИВАТНЫЙ ключ — его нельзя никому отправлять. Пусть сделает новый (ssh-keygen -t ed25519) и пришлёт строку из файла .pub.":
        "This is a PRIVATE key — never send it to anyone. Ask them to make a new key "
        "(ssh-keygen -t ed25519) and send you the line from the .pub file.",
    "Это не публичный SSH-ключ. Нужна одна строка, которая начинается с ssh-ed25519 или ssh-rsa.":
        "This is not a public SSH key. Send one line that starts with ssh-ed25519 or ssh-rsa.",
    "Это отдельная учётка, меню её не меняет.": "This account is not managed by this menu.",
    "Эти строки в {0} kilt не меняет — их правят только вручную.":
        "kilt does not change these lines in {0}. You can only edit them by hand.",
    "Это последний ключ root — без него на сервер никто не зайдёт. Сначала добавь другой.":
        "This is the last root key — without it nobody can log in. Add another key first.",
    "Этот ключ уже есть: {0}.": "This key is already used: {0}.",
    "без имени": "no name",
    "без проектов": "no projects",
    "без проектов, только осмотреться": "no projects, can only look around",
    "весь сервер — root": "whole server — root",
    "вид проекта {0} не удалось примонтировать безопасно": "could not safely mount the project folder {0}",
    "добавлен {0} (root) {1}": "added {0} (root) {1}",
    "добавлен {0}: {1} {2}": "added {0}: {1} {2}",
    "доступ к проектам": "access to projects",
    "забрать доступ": "remove access",
    "закончились свободные номера (UID/GID)": "no free numbers (UID/GID) left",
    "заменить ключ": "change key",
    "какой проект дать? (↑↓ и Enter)": "which project? (↑↓ and Enter)",
    "ключи и сеть: {0}": "keys and network: {0}",
    "кто это, например, Anna": "who is it, for example Anna",
    "латиницей, например, ivan": "Latin letters, for example ivan",
    "не найдена программа {0}": "program {0} not found",
    "нет": "none",
    "нет доступа": "no access",
    "нужен systemd": "you need systemd",
    "обычный": "normal",
    "проверка общих папок: {0}": "shared folder check: {0}",
    "проект {0}: {1}": "project {0}: {1}",
    "проект {0}: не удалось поставить права, объектов: {1}": "project {0}: could not set permissions on {1} files and folders",
    "строка ssh-ed25519 AAAA…, которую он прислал": "the line ssh-ed25519 AAAA… they sent you",
    "только осмотреться на сервере (без проектов)": "only look around the server (no projects)",
    "удалить пользователя": "delete user",
    "удалён {0} (root) {1}, закрыто сессий: {2}": "removed {0} (root) {1}, sessions closed: {2}",
    "уже выбрано — {0}. Добавить ещё проект?": "already chosen: {0}. Add one more project?",
    "учётку {0} удалить не удалось — вход закрыт, но запись осталась, проверь вручную":
        "could not delete account {0} — login is blocked, but the account is still there, check it by hand",
    "фаервол: в ядре нет nft_fib_inet — адреса сервера взяты списком, новые появятся после синхронизации":
        "firewall: the kernel has no nft_fib_inet — kilt uses a list of server addresses; "
        "new addresses are added at the next sync",
    "фаервол: исключения не посчитаны ({0}), действуют одни запреты":
        "firewall: could not work out the exceptions ({0}), so only the blocks are active",
    "чтение": "read",
    "← назад": "← back",
    "{0}: language — en или ru": "{0}: language — must be en or ru",
    "── не через это меню ──": "── not managed by this menu ──",
    "✓ {0} удалён": "✓ {0} deleted",
    "✓ {0}: весь сервер, root": "✓ {0}: whole server, root",
    "✓ {0}: ключ убран": "✓ {0}: key removed",
    "✓ Ключ заменён, старые сессии закрыты": "✓ Key changed, old sessions closed",
    "Ключ заменён, но закрыть все старые сессии не удалось": "The key is changed, but kilt could not close all old sessions",
    "файл не найден: {0}": "file not found: {0}",
    "✓ готово — дальше к ключу": "✓ done — next: the key",
    "➕ Добавить человека": "➕ Add a person",
}


# ---------------------------------------------------------------- настройки
HOST = ""
DEFAULT_CLOSED = ("/opt", "/srv")
CLOSED = list(DEFAULT_CLOSED)
SERVICE = set()
ROOT_KEYS = "/root/.ssh/authorized_keys"
BACKUPS = "/root/.ssh/kilt-backups"
LOG = "/var/log/kilt.log"
ETC = "/etc/kilt"
CONF = ETC + "/projects.json"
SETTINGS = ETC + "/config.json"
# Корни проектов закрываются целиком: системные папки и /home туда нельзя, иначе вход сломается у всех.
SYSTEM_DIRS = ("/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/libx32", "/proc",
               "/root", "/run", "/sbin", "/sys", "/usr")
MUST_STAY_OPEN = ("/home", "/tmp", "/var", "/var/log", "/var/tmp")
SYSCTL = "/etc/sysctl.d/90-kilt.conf"
STATE = ETC + "/state.json"
KEYS_DIR = ETC + "/keys"
LOCK = "/run/kilt.lock"
VIEW = "/run/kilt/view"
GROUP_ALL = "kilt"
UID_MIN, UID_MAX = 70000, 79999
GID_MIN, GID_MAX = 80000, 89999
ROOT_GROUPS = ("sudo", "wheel", "admin", "docker", "lxd", "libvirt", "disk")
RESERVED = {"root", "kilt", "adm", "staff", "nobody", *ROOT_GROUPS}
SECRET_RE = re.compile(r"((^|[._-])env($|[._-])|\.pem$|\.key$|\.p12$|\.pfx$|\.jks$|\.keystore$"
                       r"|^id_(rsa|ed25519|ecdsa)|credential|secret|passw|token)", re.I)
NOT_SECRET_RE = re.compile(r"\.(example|sample|template)$", re.I)
VENDORED = {"node_modules", ".git", "site-packages", "vendor", ".venv", "venv"}
KEY_RE = re.compile(r"^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)"
                    r"|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)\s+([A-Za-z0-9+/=]+)(\s+.*)?$")
ANYKEY_RE = re.compile(r"(ssh-(?:ed25519|rsa|dss)|ecdsa-sha2-nistp\d+|sk-\S+)\s+([A-Za-z0-9+/=]+)(\s+.*)?$")
LOGIN_RE = re.compile(r"^[a-z][a-z0-9_-]{1,30}$")
P_LEVEL = {"read": _("чтение"), "rw": _("root на проект")}
LIMITS = "[Slice]\nTasksMax=256\nMemoryHigh=768M\nMemoryMax=1G\nMemorySwapMax=0\nCPUQuota=100%\nSocketBindDeny=any\n"
RW_WARNING = (_("«root на проект» — это полное доверие: человек меняет файлы проекта и заходит в его "
              "контейнеры, а оттуда при желании и умении может получить root на всём сервере."))


NEEDS = {"docker": _("Docker Engine и docker compose v2"), "gum": "apt install gum", "nft": "apt install nftables",
         "sudo": "apt install sudo", "sshd": "apt install openssh-server", "ssh-keygen": "apt install openssh-client",
         "systemctl": _("нужен systemd"), "loginctl": _("нужен systemd"), "ip": "apt install iproute2"}


def missing(prog):
    hint = NEEDS.get(os.path.basename(str(prog or "")), "")
    return _("не найдена программа {0}").format(clean(prog, 60)) + (_(" — установи: {0}").format(hint) if hint else "")


def run(*cmd, check=True, **kw):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    except FileNotFoundError:
        raise RuntimeError(missing(cmd[0]))
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}: {(r.stderr or r.stdout).strip()}")
    return r.stdout


def clean(s, limit=200):
    return "".join(c for c in str(s) if c.isprintable())[:limit]


def log(msg):
    who = os.environ.get("SUDO_USER") or (os.environ.get("SSH_CLIENT") or "local").split()[0]
    try:
        fd = os.open(LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "a") as f:
            f.write(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [{clean(who, 40)}] {clean(msg, 500)}\n")
    except OSError:
        pass


_lock_depth, _lock_fd = 0, None


class lock:
    def __enter__(self):
        global _lock_depth, _lock_fd
        if _lock_depth == 0:
            _lock_fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            fcntl.flock(_lock_fd, fcntl.LOCK_EX)
        _lock_depth += 1

    def __exit__(self, *a):
        global _lock_depth
        _lock_depth -= 1
        if _lock_depth == 0:
            os.close(_lock_fd)


def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return default


def load_root_json(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError as e:
        raise RuntimeError(_("{0}: не открывается ({1}) — нужен обычный файл, не ссылка").format(path, e.strerror))
    try:
        with os.fdopen(fd) as f:
            st = os.fstat(f.fileno())
            if st.st_uid != 0 or st.st_mode & 0o022:
                raise RuntimeError(_("{0}: владелец должен быть root, запись — только для root").format(path))
            data = json.load(f)
    except ValueError as e:
        raise RuntimeError(_("{0}: не JSON ({1})").format(path, e))
    except OSError as e:
        raise RuntimeError(_("{0}: не открывается ({1}) — нужен обычный файл, не ссылка").format(path, e.strerror))
    if not isinstance(data, dict):
        raise RuntimeError(_("{0}: ожидается объект {{...}}").format(path))
    return data


def default_closed():
    return [d for d in DEFAULT_CLOSED if os.path.isdir(d)]


def load_settings():
    cfg = load_root_json(SETTINGS) or {}
    host = cfg.get("host") or ""
    if not isinstance(host, str) or not re.fullmatch(r"[A-Za-z0-9.:_-]{0,253}", host):
        raise RuntimeError(_("{0}: host — имя или адрес сервера").format(SETTINGS))
    if not host:
        host = (run("hostname", "-I", check=False).split() or [os.uname().nodename])[0]
    closed = cfg["closed"] if "closed" in cfg else default_closed()
    if not isinstance(closed, list) or not all(isinstance(x, str) for x in closed) or ("closed" in cfg and not closed):
        raise RuntimeError(_("{0}: closed — непустой список папок").format(SETTINGS))
    roots = []
    for d in closed:
        r = os.path.realpath(d) if os.path.isabs(d) else ""
        if not r or not os.path.isdir(r):
            raise RuntimeError(_("{0}: {1} — нужна существующая папка с полным путём").format(SETTINGS, clean(d, 80)))
        if r == "/" or any(r == x or r.startswith(x + "/") for x in SYSTEM_DIRS) \
                or any(r == x or x.startswith(r + "/") for x in MUST_STAY_OPEN):
            raise RuntimeError(_("{0}: {1} нельзя закрывать целиком — там система или домашние папки людей").format(SETTINGS, r))
        for u in pwd.getpwall():
            if UID_MIN <= u.pw_uid <= UID_MAX and (u.pw_dir == r or u.pw_dir.startswith(r + "/")):
                raise RuntimeError(_("{0}: в {1} лежит домашняя папка {2}").format(SETTINGS, r, u.pw_name))
        roots.append(r)
    if cfg.get("language", "") not in ("", "en", "ru"):
        raise RuntimeError(_("{0}: language — en или ru").format(SETTINGS))
    service = cfg.get("service_keys", [])
    if not isinstance(service, list) or not all(isinstance(x, str) for x in service):
        raise RuntimeError(_("{0}: service_keys — список комментариев ключей").format(SETTINGS))
    return host, roots, set(service)


def write_root_file(path, body, mode=0o600, group=0):
    # Точка в имени: sudo не читает такие файлы из /etc/sudoers.d, пока они не готовы.
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".kilt-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            os.fchmod(fd, mode)
            os.fchown(fd, 0, group)
            f.write(body.encode("utf-8", "surrogateescape"))
            f.flush()
            os.fsync(fd)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def alloc_id(key, lo, hi):
    st = load_json(STATE, {})
    taken = {p.pw_uid for p in pwd.getpwall()} | {g.gr_gid for g in grp.getgrall()}
    n = max(int(st.get(key, lo)), lo)
    while n in taken:
        n += 1
    if n > hi:
        raise RuntimeError(_("закончились свободные номера (UID/GID)"))
    state_set(**{key: n + 1})
    return n


def state_set(**kw):
    st = load_json(STATE, {})
    st.update(kw)
    write_root_file(STATE, json.dumps(st, ensure_ascii=False), 0o600)


def members(group):
    try:
        g = grp.getgrnam(group)
    except KeyError:
        return set()
    return set(g.gr_mem) | {p.pw_name for p in pwd.getpwall() if p.pw_gid == g.gr_gid}


def gid_of(group):
    try:
        return grp.getgrnam(group).gr_gid
    except KeyError:
        if group == GROUP_ALL:
            run("groupadd", group)
        else:
            run("groupadd", "-g", str(alloc_id("next_gid", GID_MIN, GID_MAX)), group)
        return grp.getgrnam(group).gr_gid


# ---------------------------------------------------------------- права на файлы (POSIX ACL) без гонок
# Права ставятся на уже открытый объект (O_PATH|O_NOFOLLOW): у setfacl -R между проверкой имени
# и записью папку можно подменить ссылкой на /root или /etc.
ACL_ACCESS, ACL_DEFAULT = "system.posix_acl_access", "system.posix_acl_default"
T_USER_OBJ, T_USER, T_GROUP_OBJ, T_GROUP, T_MASK, T_OTHER = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
UNDEF = 0xFFFFFFFF


def _acl_get(fd, name):
    try:
        blob = os.getxattr(f"/proc/self/fd/{fd}", name)
    except OSError as e:
        if e.errno in (errno.ENODATA, errno.EOPNOTSUPP):
            return None
        raise
    if len(blob) < 4 or struct.unpack_from("<I", blob)[0] != 2:
        return None
    return [struct.unpack_from("<HHI", blob, 4 + 8 * i) for i in range((len(blob) - 4) // 8)]


def _acl_from_mode(mode):
    return [(T_USER_OBJ, (mode >> 6) & 7, UNDEF), (T_GROUP_OBJ, (mode >> 3) & 7, UNDEF), (T_OTHER, mode & 7, UNDEF)]


def acl_apply(fd, st, want, default=False):
    name = ACL_DEFAULT if default else ACL_ACCESS
    cur = _acl_get(fd, name)
    if not cur:
        base = (_acl_get(fd, ACL_ACCESS) if default else None) or _acl_from_mode(st.st_mode)
        cur_cmp, d = None, {(t, i): p for t, p, i in base if t in (T_USER_OBJ, T_GROUP_OBJ, T_OTHER)}
    else:
        cur_cmp, d = cur, {(t, i): p for t, p, i in cur}
    for gid, perm in want.items():
        d[(T_GROUP, gid)] = perm
    mask = 0
    for (t, _q), p in d.items():
        if t in (T_USER, T_GROUP_OBJ, T_GROUP):
            mask |= p
    d[(T_MASK, UNDEF)] = mask
    order = lambda e: (e[0], e[2])
    new = sorted(((t, p, i) for (t, i), p in d.items()), key=order)
    if cur_cmp is not None and sorted(cur_cmp, key=order) == new:
        return False
    blob = struct.pack("<I", 2) + b"".join(struct.pack("<HHI", t, p, i) for t, p, i in new)
    os.setxattr(f"/proc/self/fd/{fd}", name, blob)
    return True


def open_nofollow(path):
    fd = os.open("/", os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in [p for p in path.split("/") if p]:
            if part in (".", ".."):
                raise RuntimeError(_("{0}: недопустимый путь").format(path))
            nfd = os.open(part, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = nfd
            if stat.S_ISLNK(os.fstat(fd).st_mode):
                raise RuntimeError(_("{0}: на пути символическая ссылка — root туда не пишет").format(path))
        return fd
    except BaseException:
        os.close(fd)
        raise


def acl_path(path, want):
    fd = open_nofollow(path)
    try:
        acl_apply(fd, os.fstat(fd), want)
    finally:
        os.close(fd)


def acl_tree(path, gid_r, gid_w, hide, files_ro=False, skip=()):
    """Чтение: r-X без секретов. Root на проект: rwX, секреты только читать, в .git не писать (git-хуки)."""
    rootfd = open_nofollow(path)
    dev = os.fstat(rootfd).st_dev
    res = {"seen": 0, "changed": 0, "errors": 0}
    other_projects = set()
    for d in skip:
        try:
            st = os.stat(d)
            other_projects.add((st.st_dev, st.st_ino))
        except OSError:
            pass

    def hidden(rel, name):
        return any(name == h or rel == h or fnmatch.fnmatch(rel, h) for h in hide)

    def visit(fd, rel, st, in_git, vendored, in_secret):
        is_dir = stat.S_ISDIR(st.st_mode)
        parts = rel.split("/")
        name = parts[-1]
        secret = in_secret or (not is_dir and name == "config" and ".git" in parts[:-1]) \
            or (is_dir and name == ".ssh") \
            or (not vendored and bool(SECRET_RE.search(name)) and not NOT_SECRET_RE.search(name))
        x = 1 if (is_dir or st.st_mode & 0o111) else 0
        pr = 0 if (secret or (rel and hidden(rel, name))) else 4 | x
        pw = 4 if (secret and not is_dir) else (4 | x if (in_git or files_ro) else 6 | x)
        res["seen"] += 1
        try:
            ch = acl_apply(fd, st, {gid_r: pr, gid_w: pw})
            if is_dir:
                ch |= acl_apply(fd, st, {gid_r: 1 if pr else 0, gid_w: pw}, default=True)
            res["changed"] += ch
        except OSError:
            res["errors"] += 1
        if not is_dir:
            return
        try:
            dfd = os.open(f"/proc/self/fd/{fd}", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        except OSError:
            res["errors"] += 1
            return
        try:
            for n in os.listdir(dfd):
                try:
                    cfd = os.open(n, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
                except OSError:
                    continue
                try:
                    cst = os.fstat(cfd)
                    if cst.st_dev != dev or not (stat.S_ISDIR(cst.st_mode) or stat.S_ISREG(cst.st_mode)):
                        continue
                    # Жёсткая ссылка на файл root (например, /etc/shadow) — права на неё открыли бы оригинал.
                    if stat.S_ISREG(cst.st_mode) and cst.st_nlink > 1 and cst.st_uid == 0:
                        continue
                    if (cst.st_dev, cst.st_ino) in other_projects:
                        try:
                            res["changed"] += acl_apply(cfd, cst, {gid_r: 0, gid_w: 0})
                        except OSError:
                            res["errors"] += 1
                        continue
                    visit(cfd, f"{rel}/{n}" if rel else n, cst, in_git or n == ".git", vendored or n in VENDORED, secret)
                except RecursionError:
                    res["errors"] += 1
                finally:
                    os.close(cfd)
        finally:
            os.close(dfd)

    try:
        visit(rootfd, "", os.fstat(rootfd), False, False, False)
    finally:
        os.close(rootfd)
    return res


# ---------------------------------------------------------------- ключи
def key_info(line):
    key = " ".join(str(line).replace("\r", " ").split())
    if "PRIVATE KEY" in key:
        return None, (_("Это ПРИВАТНЫЙ ключ — его нельзя никому отправлять. Пусть сделает новый "
                      "(ssh-keygen -t ed25519) и пришлёт строку из файла .pub."))
    m = KEY_RE.match(key)
    if not m or any(not c.isprintable() for c in key):
        return None, _("Это не публичный SSH-ключ. Нужна одна строка, которая начинается с ssh-ed25519 или ssh-rsa.")
    try:
        blob = base64.b64decode(m.group(2), validate=True)
        n = struct.unpack(">I", blob[:4])[0]
        if blob[4:4 + n].decode() != m.group(1):
            raise ValueError
        if m.group(1) == "ssh-rsa":
            off = 4 + n
            elen = struct.unpack(">I", blob[off:off + 4])[0]
            off += 4 + elen
            nlen = struct.unpack(">I", blob[off:off + 4])[0]
            bits = len(blob[off + 4:off + 4 + nlen].lstrip(b"\0")) * 8
            if bits < 2048:
                return None, _("RSA-ключ слишком короткий ({0} бит). Нужен ed25519 или RSA от 2048 бит.").format(bits)
    except Exception:
        return None, _("Ключ повреждён: скопирован не целиком или с лишними символами.")
    try:
        r = subprocess.run(["ssh-keygen", "-l", "-f", "-"], input=key + "\n", capture_output=True, text=True)
    except FileNotFoundError:
        return None, missing("ssh-keygen")
    if r.returncode:
        return None, _("ssh-keygen не признал эту строку ключом.")
    return key, "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def fingerprint(line):
    m = ANYKEY_RE.search(str(line).strip())
    if not m:
        return None
    try:
        return "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(m.group(2))).digest()).decode().rstrip("=")
    except Exception:
        return None


def root_key_lines():
    try:
        with open(ROOT_KEYS, encoding="utf-8", errors="surrogateescape", newline="") as f:
            lines = f.read().splitlines(keepends=True)
    except FileNotFoundError:
        return []
    out = []
    for line in lines:
        s = line.strip()
        m = ANYKEY_RE.match(s)
        fp = fingerprint(s) if m and "-cert-" not in m.group(1) else None
        if not fp:
            out.append((line, None))
            continue
        raw, name = line, None
        if out and out[-1][1] is None and out[-1][0].lstrip().startswith("#"):
            prev = out.pop()[0]
            raw, name = prev + line, prev.strip().lstrip("#").strip() or None
        comment = (m.group(3) or "").strip()
        out.append((raw, {"name": clean(name or comment or _("без имени"), 60), "key": s, "fp": fp,
                          "service": comment in SERVICE}))
    return out


def root_keys():
    return [e for _raw, e in root_key_lines() if e]


def write_root_keys(entries):
    want = {e.get("fp") or fingerprint(e["key"]): e for e in entries}
    lines = root_key_lines()
    body = "".join(raw for raw, e in lines if not e or e["fp"] in want)
    if body and not body.endswith("\n"):
        body += "\n"
    have = {e["fp"] for _raw, e in lines if e}
    body += "".join(("" if e.get("service") else f"#{e['name']}\n") + e["key"] + "\n"
                    for fp, e in want.items() if fp not in have)
    os.makedirs(BACKUPS, mode=0o700, exist_ok=True)
    if os.path.exists(ROOT_KEYS):
        shutil.copy2(ROOT_KEYS, f"{BACKUPS}/root-{datetime.datetime.now():%Y%m%d-%H%M%S}", follow_symlinks=False)
        for old in sorted(f for f in os.listdir(BACKUPS) if f.startswith("root-"))[:-100]:
            os.remove(os.path.join(BACKUPS, old))
    os.makedirs(os.path.dirname(ROOT_KEYS), mode=0o700, exist_ok=True)
    write_root_file(ROOT_KEYS, body, 0o600)


def key_owner(fp):
    for e in root_keys():
        if e["fp"] == fp:
            return _("{0} (весь сервер, root)").format(e['name'])
    for u in accounts():
        if u["fp"] == fp:
            return _("{0} (личная учётка)").format(u['login'])
    return None


# ---------------------------------------------------------------- проекты
def safe_dir(d):
    if not d or not os.path.isabs(d):
        return None
    r = os.path.realpath(d)
    for root in CLOSED:
        if r.startswith(os.path.realpath(root) + "/") and os.path.isdir(r):
            return r
    return None


def load_projects_conf():
    conf = load_root_json(CONF) or {}
    for k, v in conf.items():
        if not isinstance(v, dict) or any(f in v and not isinstance(v[f], str) for f in ("compose", "dir")) \
                or not (isinstance(v.get("hide", []), list) and all(isinstance(h, str) for h in v.get("hide", []))) \
                or v.get("files", "ro") != "ro":
            raise RuntimeError(_("{0}: проект {1} — ожидается объект с полями compose (строка), dir (строка), "
                                 "hide (список строк), files (только \"ro\")").format(CONF, clean(k, 40)))
    return conf


def projects():
    conf = {k: v for k, v in load_projects_conf().items()
            if re.fullmatch(r"[a-z0-9][a-z0-9-]{0,23}", k) and not k.endswith("-rw")}
    by_compose = {(v.get("compose") or k): k for k, v in conf.items()}
    fmt = '{{.Label "com.docker.compose.project"}}|{{.Label "com.docker.compose.project.working_dir"}}|' \
          '{{.Label "com.docker.compose.service"}}|{{.Names}}|{{.ID}}'
    out = {}
    for line in run("docker", "ps", "-a", "--format", fmt).splitlines():
        comp, wd, svc, cname, cid = (line.split("|") + [""] * 5)[:5]
        if not comp:
            continue
        name = by_compose.get(comp)
        if not name:
            name = re.sub(r"[^a-z0-9-]", "-", comp.lower()).strip("-")[:24]
            if name.endswith("-rw"):
                name += "-p"
            if not name:
                continue
            if name in conf or (name in out and out[name]["compose"] != comp):
                name = name[:18] + "-" + hashlib.sha1(comp.encode()).hexdigest()[:5]
        p = out.setdefault(name, {"compose": comp, "dir": conf.get(name, {}).get("dir") or wd, "services": {}, "ids": []})
        if p["compose"] != comp:
            continue
        p["services"].setdefault(svc, []).append(cname)
        p["ids"].append(cid)
    for name, v in conf.items():
        if name not in out and v.get("dir"):
            out[name] = {"compose": v.get("compose") or name, "dir": v["dir"], "services": {}, "ids": []}
    for name in list(out):
        d = safe_dir(out[name]["dir"])
        if not d:
            del out[name]
            continue
        out[name]["dir"] = d
        out[name]["hide"] = list(conf.get(name, {}).get("hide", []))
        out[name]["files_ro"] = conf.get(name, {}).get("files") == "ro"
    return out


def docker_inspect(ids):
    if not ids:
        return []
    # Контейнер мог исчезнуть после docker ps: inspect тогда падает, но остальные всё равно выводит.
    try:
        data = json.loads(run("docker", "inspect", *ids, check=False) or "[]")
    except ValueError:
        return []
    return [c for c in data if isinstance(c, dict)] if isinstance(data, list) else []


def project_net(p):
    ips, ports, pairs, hostports = set(), set(), set(), set()
    for c in docker_inspect(p.get("ids")):
        ns = c.get("NetworkSettings") or {}
        mine = {n.get("IPAddress") for n in (ns.get("Networks") or {}).values()
                if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", n.get("IPAddress") or "")}
        ips |= mine
        for spec, binds in (ns.get("Ports") or {}).items():
            port = spec.split("/")[0]
            if port.isdigit():
                pairs |= {f"{ip}:{port}" for ip in mine}
            for b in binds or []:
                hp, hip = str(b.get("HostPort", "")), b.get("HostIp") or ""
                if not hp.isdigit():
                    continue
                if hip in ("", "0.0.0.0", "::"):
                    ports.add(int(hp))
                elif re.fullmatch(r"\d+\.\d+\.\d+\.\d+", hip):
                    hostports.add(f"{hip}:{hp}")
    return ips, ports, pairs, hostports


def groups_of(name):
    return f"p-{name}", f"p-{name}-rw"


def ensure_closed():
    for root in CLOSED:
        if os.path.isdir(root):
            acl_path(root, {gid_of(GROUP_ALL): 0})


def other_dirs(allp, name):
    return [v["dir"] for n, v in allp.items() if n != name and v.get("dir")]


def apply_acl(name, p, skip=()):
    gr, grw = groups_of(name)
    g_r, g_w = gid_of(gr), gid_of(grw)
    d = p["dir"]
    ensure_closed()
    root = next(r for r in map(os.path.realpath, CLOSED) if d.startswith(r + "/"))
    cur = root
    for part in os.path.relpath(d, root).split("/"):
        acl_path(cur, {g_r: 0, g_w: 0})
        cur = os.path.join(cur, part)
    return acl_tree(d, g_r, g_w, p.get("hide") or [], p.get("files_ro", False), skip)


def view_path(name):
    return f"{VIEW}/{name}/m"


def mount_table():
    out = {}
    with open("/proc/self/mountinfo") as f:
        for line in f:
            parts = line.split()
            out[parts[4]] = set(parts[5].split(","))
    return out


def view_ok(name, p):
    target = view_path(name)
    table = mount_table()
    try:
        real, st = os.stat(p["dir"]), os.stat(target)
    except OSError:
        return False
    return target in table and {"nosuid", "nodev"} <= table[target] \
        and (st.st_dev, st.st_ino) == (real.st_dev, real.st_ino) and gate_ok(name)


def gate_ok(name):
    try:
        st = os.lstat(f"{VIEW}/{name}")
        gid = grp.getgrnam(groups_of(name)[0]).gr_gid
    except (OSError, KeyError):
        return False
    return stat.S_ISDIR(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o750 and st.st_uid == 0 and st.st_gid == gid


def ensure_view(name, p):
    """Проект виден людям только через монтирование с nosuid,nodev: setuid-файл или устройство из контейнера не сработают."""
    if view_ok(name, p):
        return
    gate, target = f"{VIEW}/{name}", view_path(name)
    os.makedirs(VIEW, mode=0o755, exist_ok=True)
    for d in (os.path.dirname(VIEW), VIEW):
        os.chmod(d, 0o755)
    os.makedirs(gate, mode=0o700, exist_ok=True)
    os.chmod(gate, 0o700)
    while target in mount_table():
        run("umount", "-l", target)
    os.makedirs(target, mode=0o755, exist_ok=True)
    fd = open_nofollow(p["dir"])
    try:
        run("mount", "--bind", p["dir"], target)
        # mount открывает путь заново: папку могли подменить ссылкой между проверкой и монтированием.
        a, b = os.stat(target), os.fstat(fd)
        if (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino):
            run("umount", "-l", target, check=False)
            raise RuntimeError(_("вид проекта {0} не удалось примонтировать безопасно").format(name))
    finally:
        os.close(fd)
    run("mount", "-o", "remount,bind,nosuid,nodev", target)
    run("mount", "--make-private", target)
    if not {"nosuid", "nodev"} <= mount_table().get(target, set()):
        run("umount", "-l", target, check=False)
        raise RuntimeError(_("вид проекта {0} не удалось примонтировать безопасно").format(name))
    os.chown(gate, 0, gid_of(groups_of(name)[0]))
    os.chmod(gate, 0o750)


def drop_view(name):
    target = view_path(name)
    while target in mount_table():
        run("umount", "-l", target)


def risky_binds(p):
    out = set()
    roots = [os.path.realpath(r) + "/" for r in CLOSED]
    sockets = {os.path.realpath(s) + "/" for s in ("/run/docker.sock", "/var/run/docker.sock")}
    for c in docker_inspect(p.get("ids")):
        cname = clean((c.get("Name") or "").lstrip("/"), 80)
        if (c.get("HostConfig") or {}).get("Privileged"):
            out.add(("privileged", cname))
        for m in c.get("Mounts") or []:
            src = m.get("Source") or ""
            if m.get("Type") != "bind" or not src:
                continue
            real = os.path.realpath(src).rstrip("/") + "/"
            if any(s.startswith(real) for s in sockets):
                out.add(("socket", cname))
                continue
            if not m.get("RW") or any((src + "/").startswith(r) for r in roots):
                continue
            try:
                flags = os.statvfs(src).f_flag
            except OSError:
                continue
            if not (flags & os.ST_NOSUID and flags & os.ST_NODEV):
                out.add(("bind", src))
    return sorted(out)


# ---------------------------------------------------------------- личные учётки
def user_projects(login, allp):
    res = {}
    for name in allp:
        gr, grw = groups_of(name)
        if login in members(grw):
            res[name] = "rw"
        elif login in members(gr):
            res[name] = "read"
    return res


def key_file(login):
    return os.path.join(KEYS_DIR, login)


def kilt_uid(login):
    try:
        uid = pwd.getpwnam(login).pw_uid
    except KeyError:
        return None
    return uid if UID_MIN <= uid <= UID_MAX else None


def accounts():
    out = []
    for login in sorted(members(GROUP_ALL)):
        if kilt_uid(login) is None:
            continue
        key = fp = None
        try:
            with open(key_file(login)) as f:
                for line in f:
                    m = ANYKEY_RE.search(line.strip())
                    fp = fingerprint(m.group(0)) if m else None
                    if fp:
                        key = m.group(0)
                        break
        except (OSError, UnicodeDecodeError):
            pass
        out.append({"login": login, "key": key, "fp": fp})
    return out


def write_user_key(login, key, allp, mine=None):
    mine = mine if mine is not None else user_projects(login, allp)
    targets = set()
    for name, level in mine.items():
        if level == "rw":
            _ips, ports, pairs, hostports = project_net(allp[name])
            targets |= pairs | hostports | {f"127.0.0.1:{p}" for p in ports} | {f"localhost:{p}" for p in ports}
            targets |= {"localhost:" + h.split(":")[1] for h in hostports if h.startswith("127.0.0.1:")}
    opts = "restrict,pty"
    if len(targets) > 300:
        log(_("{0}: адресов для проброса портов больше 300 ({1}) — проброс портов выключен").format(login, len(targets)))
    elif targets:
        opts += ",port-forwarding," + ",".join(f'permitopen="{t}"' for t in sorted(targets))
    os.makedirs(KEYS_DIR, mode=0o755, exist_ok=True)
    write_root_file(key_file(login), f"{opts} {key}\n", 0o640, pwd.getpwnam(login).pw_gid)


def user_file(login, name, text):
    pw = pwd.getpwnam(login)
    try:
        fd = os.open(os.path.join(pw.pw_dir, name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    except OSError:
        return
    try:
        os.fchown(fd, pw.pw_uid, pw.pw_gid)
        os.write(fd, text.encode())
    finally:
        os.close(fd)


def link_projects(login, mine):
    pw = pwd.getpwnam(login)
    home = pw.pw_dir
    user_file(login, ".gitconfig", "[safe]\n\tdirectory = *\n")
    try:
        names = os.listdir(home)
    except OSError:
        return
    for f in names:
        path = os.path.join(home, f)
        try:
            if os.path.islink(path) and f not in mine and os.readlink(path).startswith(VIEW + "/"):
                os.remove(path)
        except OSError:
            pass
    for name in mine:
        path, target = os.path.join(home, name), view_path(name)
        try:
            if os.path.islink(path) and os.readlink(path) != target:
                os.remove(path)
            if not os.path.lexists(path):
                os.symlink(target, path)
                os.lchown(path, pw.pw_uid, pw.pw_gid)
        except OSError:
            pass


def kill_user(login):
    """kill(-1) от имени самого человека: ядро убивает все его процессы разом, pkill пропускает размножившиеся."""
    try:
        pw = pwd.getpwnam(login)
    except KeyError:
        return True
    if not UID_MIN <= pw.pw_uid <= UID_MAX:          # kill(-1) от root убил бы весь сервер — только учётки kilt
        raise RuntimeError(_("{0}: это не личная учётка kilt, kilt не трогает её процессы").format(login))
    for _try in range(6):
        pid = os.fork()
        if pid == 0:
            try:
                os.setgroups([])
                os.setgid(pw.pw_gid)
                os.setuid(pw.pw_uid)
                if os.getuid() == pw.pw_uid and os.geteuid() == pw.pw_uid and os.getuid() != 0:
                    os.kill(-1, signal.SIGKILL)
            finally:
                os._exit(0)
        os.waitpid(pid, 0)
        time.sleep(0.15)
        if not run("pgrep", "-u", str(pw.pw_uid), check=False).strip():
            return True
    return False


def edit_lines(path, add=None, remove=None):
    lines = []
    try:
        with open(path, encoding="utf-8", errors="surrogateescape") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        pass
    if remove:
        lines = [l for l in lines if l.strip() != remove]
    if add and add not in (l.strip() for l in lines):
        lines.append(add)
    write_root_file(path, "".join(l + "\n" for l in lines), 0o644)


def create_user(login, key):
    uid = alloc_id("next_uid", UID_MIN, UID_MAX)
    run("groupadd", "-g", str(uid), login)
    try:
        run("useradd", "-m", "-s", "/bin/bash", "-u", str(uid), "-g", str(uid), "-G", GROUP_ALL, "-c", "kilt", login)
    except RuntimeError:
        run("groupdel", login, check=False)
        raise
    run("usermod", "-p", "*", login)
    os.chmod(pwd.getpwnam(login).pw_dir, 0o700)
    edit_lines("/etc/cron.deny", add=login)
    d = f"/etc/systemd/system/user-{uid}.slice.d"
    os.makedirs(d, exist_ok=True)
    write_root_file(d + "/50-kilt.conf", LIMITS, 0o644)
    run("systemctl", "daemon-reload", check=False)
    user_file(login, ".bash_profile",
              _('[ -f ~/.bashrc ] && . ~/.bashrc\n'
                'echo; echo "Твои проекты: $(for f in ~/*; do case "$(readlink "$f")" in (/run/kilt/view/*) '
                'printf "%s " "$(basename "$f")";; esac; done)"\n'
                'echo "Контейнеры проекта: cd ~/<проект>, затем kilt ps, kilt logs -f <сервис>, kilt help"; echo\n'))
    write_user_key(login, key, {}, {})


def set_project(login, name, level, allp):
    gr, grw = groups_of(name)
    with lock():
        if level:
            apply_acl(name, allp[name], other_dirs(allp, name))
            ensure_view(name, allp[name])
            run("usermod", "-aG", gr, login)
            if level == "rw":
                run("usermod", "-aG", grw, login)
            else:
                run("gpasswd", "-d", login, grw, check=False)
        else:
            run("gpasswd", "-d", login, gr, check=False)
            run("gpasswd", "-d", login, grw, check=False)
        refresh(allp, only=login)
        if not kill_user(login):
            log(_("ВНИМАНИЕ: не удалось завершить все процессы {0}").format(login))
    log(_("{0}: проект {1} → {2}").format(login, name, P_LEVEL[level] if level else _("нет доступа")))


def delete_user(login):
    with lock():
        try:
            uid = pwd.getpwnam(login).pw_uid
        except KeyError:
            raise RuntimeError(_("Учётки {0} на сервере уже нет").format(login)) from None
        if not UID_MIN <= uid <= UID_MAX:
            raise RuntimeError(_("{0}: это не личная учётка kilt, kilt не трогает её процессы").format(login))
        if os.path.exists(key_file(login)):
            os.remove(key_file(login))
        run("usermod", "-e", "1", login, check=False)
        kill_user(login)
        run("crontab", "-r", "-u", login, check=False)
        for leftover in (f"/var/spool/cron/crontabs/{login}", f"/var/mail/{login}"):
            if os.path.lexists(leftover):
                os.remove(leftover)
        run("loginctl", "disable-linger", login, check=False)
        kill_user(login)
        run("userdel", "-r", login, check=False)
        try:
            pwd.getpwnam(login)
        except KeyError:
            pass
        else:
            raise RuntimeError(_("учётку {0} удалить не удалось — вход закрыт, но запись осталась, проверь вручную").format(login))
        run("groupdel", login, check=False)
        edit_lines("/etc/cron.deny", remove=login)
        shutil.rmtree(f"/etc/systemd/system/user-{uid}.slice.d", ignore_errors=True)
        run("systemctl", "daemon-reload", check=False)
        for tmp in ("/tmp", "/var/tmp", "/dev/shm"):
            run("find", tmp, "-xdev", "-uid", str(uid), "-delete", check=False)
        firewall()
    log(_("{0}: удалён").format(login))


# ---------------------------------------------------------------- сеть
def dns_servers():
    v4, v6 = {"127.0.0.53", "127.0.0.54"}, set()
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 2 or parts[0] != "nameserver":
                    continue
                try:
                    a = ipaddress.ip_address(parts[1].split("%")[0])
                except ValueError:
                    continue
                (v4 if a.version == 4 else v6).add(str(a))
    except (OSError, UnicodeDecodeError):
        pass
    return v4, v6


def firewall(allp=None):
    ip_el, port_el, hostport_el = set(), set(), set()
    try:
        allp = allp if allp is not None else projects()
        for u in accounts():
            uid = pwd.getpwnam(u["login"]).pw_uid
            for name, level in user_projects(u["login"], allp).items():
                if level == "rw":
                    ips, ports, _pairs, hostports = project_net(allp[name])
                    ip_el |= {f"{uid} . {ip}" for ip in ips}
                    port_el |= {f"{uid} . {p}" for p in ports}
                    hostport_el |= {f"{uid} . {h.replace(':', ' . ')}" for h in hostports}
    except Exception as e:
        log(_("фаервол: исключения не посчитаны ({0}), действуют одни запреты").format(clean(e, 120)))
        ip_el, port_el, hostport_el = set(), set(), set()
    el = lambda s: f" elements = {{ {', '.join(sorted(s))} }}" if s else ""
    dns4, dns6 = dns_servers()
    dns = "\n".join(f"        {fam} daddr {{ {', '.join(sorted(s))} }} meta l4proto {{ tcp, udp }} th dport 53 accept"
                    for fam, s in (("ip", dns4), ("ip6", dns6)) if s)

    def ruleset(local4=None, local6=None):
        if local4 is None:
            sets, to_host, to_deny = "", ["fib daddr type local"], ["fib daddr type local"]
        else:
            sets = (f"    set local4 {{ type ipv4_addr; flags interval;{el(local4)} }}\n"
                    f"    set local6 {{ type ipv6_addr; flags interval;{el(local6)} }}\n")
            to_host = to_deny = ["ip daddr @local4", "ip6 daddr @local6"]
        host = "\n".join(f"        {m} meta skuid . tcp dport @allow_port accept" for m in to_host)
        deny = "\n".join(f"        {m} jump deny" for m in to_deny)
        return f"""table inet kilt {{}}
delete table inet kilt
table inet kilt {{
    set allow_ip {{ typeof meta skuid . ip daddr;{el(ip_el)} }}
    set allow_port {{ typeof meta skuid . tcp dport;{el(port_el)} }}
    set allow_hostport {{ typeof meta skuid . ip daddr . tcp dport;{el(hostport_el)} }}
{sets}    chain output {{
        type filter hook output priority 0; policy accept;
        meta skuid {UID_MIN}-{UID_MAX} jump restricted
    }}
    chain restricted {{
        meta skuid . ip daddr @allow_ip accept
        meta skuid . ip daddr . tcp dport @allow_hostport accept
{host}
{dns}
{deny}
        ip daddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10 }} jump deny
        ip6 daddr {{ fc00::/7, fe80::/10 }} jump deny
    }}
    chain deny {{
        counter
        meta l4proto tcp reject with tcp reset
        reject with icmpx admin-prohibited
    }}
}}
"""

    def nft(rules):
        try:
            return subprocess.run(["nft", "-f", "-"], input=rules, capture_output=True, text=True)
        except FileNotFoundError:
            raise RuntimeError(missing("nft"))

    r = nft(ruleset())
    if r.returncode and "fib" in r.stderr:
        nets = [ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128")]
        for link in json.loads(run("ip", "-j", "addr", "show") or "[]"):
            for a in link.get("addr_info") or []:
                try:
                    nets.append(ipaddress.ip_network(a.get("local") or ""))
                except ValueError:
                    pass
        local4 = {str(n) for n in ipaddress.collapse_addresses(n for n in nets if n.version == 4)}
        local6 = {str(n) for n in ipaddress.collapse_addresses(n for n in nets if n.version == 6)}
        r = nft(ruleset(local4, local6))
        if not r.returncode and not load_json(STATE, {}).get("fib_warned"):
            log(_("фаервол: в ядре нет nft_fib_inet — адреса сервера взяты списком, новые появятся после синхронизации"))
            try:
                state_set(fib_warned=True)
            except OSError:
                pass
    if r.returncode:
        raise RuntimeError(f"nft: {r.stderr.strip()}")


def refresh(allp=None, only=None):
    allp = allp if allp is not None else projects()
    for u in accounts():
        if only and u["login"] != only:
            continue
        mine = user_projects(u["login"], allp)
        link_projects(u["login"], mine)
        if u["key"]:
            write_user_key(u["login"], u["key"], allp, mine)
    firewall(allp)


def sync():
    errors = []
    try:
        _soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
    except (ValueError, OSError):
        pass
    with lock():
        try:
            ensure_closed()
            allp = projects()
        except Exception as e:
            log(f"sync: {clean(e)}")
            print(f"kilt sync: {clean(e)}", file=sys.stderr)
            try:
                firewall({})
            except Exception:
                pass
            return 1
        used = set()
        for u in accounts():
            try:
                used |= set(user_projects(u["login"], allp))
            except Exception as e:
                errors.append(f"{u['login']}: {e}")
        for name in sorted(used):
            try:
                res = apply_acl(name, allp[name], other_dirs(allp, name))
                ensure_view(name, allp[name])
                if res["errors"]:
                    errors.append(_("проект {0}: не удалось поставить права, объектов: {1}").format(name, res['errors']))
            except Exception as e:
                errors.append(_("проект {0}: {1}").format(name, e))
        try:
            for name in (os.listdir(VIEW) if os.path.isdir(VIEW) else []):
                if name not in used:
                    drop_view(name)
            refresh(allp)
        except Exception as e:
            errors.append(_("ключи и сеть: {0}").format(e))
        try:
            warned = set(load_json(STATE, {}).get("warned", []))
            says = {
                "bind": _("ВНИМАНИЕ: проект {0}: общая с контейнером папка {1} вне защищённых каталогов, без nosuid или nodev — "
                          "человек с «root на проект» может через неё получить root на сервере"),
                "socket": _("ВНИМАНИЕ: проект {0}: контейнер {1} получил сокет Docker — "
                            "человек с «root на проект» может через него получить root на сервере"),
                "privileged": _("ВНИМАНИЕ: проект {0}: контейнер {1} запущен с privileged — "
                                "человек с «root на проект» может через него получить root на сервере"),
            }
            for name in sorted(used):
                for kind, what in risky_binds(allp[name]):
                    if f"{name}:{kind}:{what}" not in warned:
                        warned.add(f"{name}:{kind}:{what}")
                        log(says[kind].format(name, what))
            state_set(warned=sorted(warned), dirs={n: v["dir"] for n, v in allp.items()})
        except Exception as e:
            errors.append(_("проверка общих папок: {0}").format(e))
    for e in errors:
        log(f"sync: {clean(e)}")
        print(f"kilt sync: {clean(e)}", file=sys.stderr)
    return 1 if errors else 0


def boot():
    with lock():
        try:
            firewall()
        except Exception as e:
            log(_("boot: фаервол: {0}").format(clean(e)))
        try:
            allp = projects()
        except Exception:
            allp = {n: {"dir": d, "ids": [], "services": {}} for n, d in load_json(STATE, {}).get("dirs", {}).items()
                    if safe_dir(d) == d}
        used = set()
        for u in accounts():
            used |= set(user_projects(u["login"], allp))
        for name in sorted(used):
            try:
                ensure_view(name, allp[name])
            except Exception as e:
                log(_("boot: вид проекта {0}: {1}").format(name, clean(e)))
    return 0


# ---------------------------------------------------------------- контейнеры (личная учётка → sudo kilt containers …)
CONTAINER_CMDS = {"ps", "logs", "restart", "stop", "start", "exec", "-p"}
CONTAINER_HELP = _("""kilt — контейнеры твоего проекта. Проект берётся из папки, где ты стоишь (cd ~/shop), или kilt -p <проект> …

  kilt ps                         какие контейнеры и в каком состоянии
  kilt logs [флаги] [сервис…]     журнал контейнеров; флаги: -f, -t, --tail N, --since, --until
  kilt restart|stop|start сервис… только с правами «root на проект»
  kilt exec сервис [команда…]     зайти в контейнер (по умолчанию sh), только «root на проект»
""")


def as_user(args):
    try:
        mine = {grp.getgrgid(g).gr_name for g in os.getgroups()}
    except KeyError:
        mine = set()
    if GROUP_ALL not in mine:
        sys.exit(_("kilt: меню kilt запускается от root (ssh root@сервер, затем kilt). "
                 "Команды контейнеров есть только у личных учёток kilt."))
    try:
        os.execv("/usr/bin/sudo", ["sudo", "-n", "/usr/local/bin/kilt", "containers", *args])
    except FileNotFoundError:
        sys.exit(_("Ошибка: {0}").format(missing('sudo')))


def container_cmd(args):
    sudo_uid = os.environ.get("SUDO_UID", "")
    if sudo_uid.isdigit() and int(sudo_uid) != 0:
        try:
            user = pwd.getpwuid(int(sudo_uid)).pw_name
        except KeyError:
            sys.exit(_("kilt: непонятно, кто вызывает"))
        # Админ после sudo -i и так root; учётку kilt (по группе или по номеру) за root не принимаем никогда.
        if user not in members(GROUP_ALL) and not UID_MIN <= int(sudo_uid) <= UID_MAX:
            user = "root"
    elif os.getuid() == 0:
        user = "root"
    else:
        sys.exit(_("kilt: непонятно, кто вызывает"))
    try:
        cwd = os.path.realpath(os.getcwd())
    except OSError:
        cwd = "/"
    # docker работает от root: окружение и текущая папка человека не должны на него влиять.
    term = re.sub(r"[^A-Za-z0-9._-]", "", os.environ.get("TERM", "")) or "xterm"
    os.environ.clear()
    os.environ.update({"HOME": "/root", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "TERM": term,
                       "SUDO_USER": user})
    os.chdir("/")
    allp = projects()
    mine = {n: "rw" for n in allp} if user == "root" else user_projects(user, allp)
    name = None
    if args[:1] == ["-p"]:
        if len(args) < 2 or args[1].startswith("-"):
            sys.exit(_("kilt -p <проект> <команда> …"))
        name, args = args[1], args[2:]
    if not name:
        real = cwd
        for n, v in allp.items():
            if cwd == view_path(n) or cwd.startswith(view_path(n) + "/"):
                real = v["dir"] + cwd[len(view_path(n)):]
        best = ""
        for n in mine:
            d = allp[n]["dir"]
            if (real == d or real.startswith(d + "/")) and len(d) > len(best):
                name, best = n, d
    if not name and len(mine) == 1:
        name = next(iter(mine))
    if not args or args[0] in ("help", "-h", "--help"):
        print(CONTAINER_HELP + _("\nТвои проекты: ") + (", ".join(f"{n} ({P_LEVEL[l]})" for n, l in mine.items()) or _("нет")))
        return 0
    if not name:
        sys.exit(_("Непонятно, какой проект: зайди в его папку (cd ~/<проект>) или укажи kilt -p <проект> …"))
    if name not in mine:
        sys.exit(_("У тебя нет доступа к проекту {0}").format(clean(name, 40)))
    p, level = allp[name], mine[name]
    cmd, rest = args[0], args[1:]
    if cmd in ("ps", "logs") and not p["services"]:
        sys.exit(_("У проекта {0} нет контейнеров.").format(name))
    if user != "root" and not view_ok(name, p):
        try:
            with lock():
                ensure_view(name, p)
        except Exception as e:
            log(_("контейнеры: вид проекта {0}: {1}").format(name, clean(e)))

    def containers(services):
        if not services:
            return [c for cs in p["services"].values() for c in cs]
        out = []
        for s in services:
            if s not in p["services"]:
                sys.exit(_("Нет сервиса {0}. Есть: {1}").format(clean(s, 60), ', '.join(sorted(p['services']))))
            out += p["services"][s]
        return out

    if cmd == "ps":
        os.execvp("docker", ["docker", "ps", "-a", "--filter", f"label=com.docker.compose.project={p['compose']}",
                             "--format", "table {{.Label \"com.docker.compose.service\"}}\t{{.Status}}\t{{.Ports}}"])
    if cmd == "logs":
        flags, svcs, i = [], [], 0
        while i < len(rest):
            a = rest[i]
            if a in ("-f", "--follow", "-t", "--timestamps"):
                flags.append(a)
            elif a in ("--tail", "-n", "--since", "--until") and i + 1 < len(rest) \
                    and re.fullmatch(r"[A-Za-z0-9:.+T-]{1,40}", rest[i + 1]) and not rest[i + 1].startswith("-"):
                flags += [a, rest[i + 1]]
                i += 1
            elif a.startswith("-"):
                sys.exit(_("Флаг {0} не поддерживается").format(clean(a, 40)))
            else:
                svcs.append(a)
            i += 1
        containers(svcs)
        os.execvp("docker", ["docker", "compose", "-p", p["compose"], "logs", *flags, "--", *svcs])
    if level != "rw":
        sys.exit(_("Команда {0} доступна только с правами «root на проект». У тебя: {1}.").format(clean(cmd, 20), P_LEVEL[level]))
    if cmd in ("restart", "stop", "start"):
        if not rest:
            sys.exit(_("Укажи сервис: kilt {0} <сервис>. Есть: {1}").format(cmd, ', '.join(sorted(p['services']))))
        if any(a.startswith("-") for a in rest):
            sys.exit(_("Флаги здесь не поддерживаются"))
        log(f"containers {name}: {cmd} {' '.join(rest)}")
        code = subprocess.run(["docker", cmd, *containers(rest)]).returncode
        try:
            with lock():
                refresh()
        except Exception as e:
            log(_("контейнеры: обновление правил не удалось: {0}").format(clean(e)))
        return code
    if cmd == "exec":
        if not rest or rest[0].startswith("-"):
            sys.exit(_("kilt exec <сервис> [команда…]"))
        c = containers([rest[0]])[0]
        log(f"containers {name}: exec {' '.join(rest)}")
        tty = ["-it"] if sys.stdin.isatty() else ["-i"]
        os.execvp("docker", ["docker", "exec", *tty, c, *(rest[1:] or ["sh"])])
    sys.exit(_("Неизвестная команда {0}. kilt help — список.").format(clean(cmd, 20)))


# ---------------------------------------------------------------- gum
def gum(*args):
    try:
        termios.tcflush(0, termios.TCIFLUSH)
    except Exception:
        pass
    r = subprocess.run(["gum", *args], stdout=subprocess.PIPE, text=True)
    return r.stdout.strip("\n") if r.returncode == 0 else None


def choose(header, items, height=25):
    items = list(items)
    shown = [clean(i) for i in items]
    pick = gum("choose", "--header", clean(header), "--height", str(height), "--", *shown)
    return items[shown.index(pick)] if pick in shown else None


def ask(prompt, placeholder=""):
    return gum("input", "--char-limit", "0", "--prompt", clean(prompt), "--placeholder", clean(placeholder))


def confirm(q, yes, no=_("Отмена")):
    try:
        termios.tcflush(0, termios.TCIFLUSH)
    except Exception:
        pass
    return subprocess.run(["gum", "confirm", clean(q, 400), "--default=false",
                           "--affirmative", yes, "--negative", no]).returncode == 0


def confirm_code(what):
    code = str(secrets.randbelow(9000) + 1000)
    return ask(_("{0} Чтобы подтвердить, введи {1}: ").format(what, code)) == code


def say(text, color="42"):
    subprocess.run(["gum", "style", "--foreground", color, "--", clean(text, 600)])


def box(*lines, color="212"):
    subprocess.run(["gum", "style", "--border", "rounded", "--padding", "1 2", "--border-foreground", color,
                    "--", *[clean(l, 300) for l in lines]])


def pause():
    ask("", _("Enter — назад"))


def fail(text):
    say(text, "196")
    pause()


# ---------------------------------------------------------------- экраны
def ask_key():
    raw = ask(_("Публичный ключ: "), _("строка ssh-ed25519 AAAA…, которую он прислал"))
    if not raw:
        return None, None
    key, fp = key_info(raw)
    if not key:
        fail(fp)
        return None, None
    who = key_owner(fp)
    if who:
        fail(_("Этот ключ уже есть: {0}.").format(who))
        return None, None
    return key, fp


def proc_stat(pid):
    with open(f"/proc/{pid}/stat") as f:
        return f.read().rsplit(")", 1)[1].split()


def kick_fp(fp):
    try:
        out = run("journalctl", "-b", "-u", "ssh", "-u", "sshd", "-o", "json", "--no-pager", check=False, timeout=30)
        hz = os.sysconf("SC_CLK_TCK")
    except Exception:
        return 0
    mine, pid = set(), os.getpid()
    while pid > 1:
        mine.add(pid)
        try:
            pid = int(proc_stat(pid)[1])
        except (OSError, IndexError, ValueError):
            break
    killed = set()
    for line in out.splitlines():
        try:
            d = json.loads(line)
            msg, pid = d.get("MESSAGE"), int(d.get("_PID", 0))
            logged = int(d.get("__MONOTONIC_TIMESTAMP", 0)) / 1e6
        except (ValueError, TypeError, AttributeError):
            continue
        if not isinstance(msg, str) or "Accepted publickey" not in msg or not msg.rstrip().endswith(" " + fp) \
                or pid <= 1 or pid in mine or pid in killed:
            continue
        try:
            with open(f"/proc/{pid}/comm") as f:
                comm = f.read().strip()
            st = proc_stat(pid)
            ppid, started = int(st[1]), int(st[19]) / hz
        except (OSError, IndexError, ValueError):
            continue
        # Не слушающий sshd (его родитель — PID 1) и не новый процесс, получивший тот же PID после входа.
        if comm not in ("sshd", "sshd-session") or ppid == 1 or started > logged + 1:
            continue
        try:
            os.kill(pid, signal.SIGTERM)
            killed.add(pid)
        except OSError:
            pass
    return len(killed)


def ask_login():
    login = ask(_("Логин: "), _("латиницей, например, ivan"))
    if not login:
        return None
    login = login.strip().lower()
    if not LOGIN_RE.match(login) or login in RESERVED or login.startswith("p-"):
        fail(_("Логин: от 2 до 31 символа, латиница в нижнем регистре, цифры, - и _, начинается с буквы; "
               "нельзя начинать с p-; служебные имена нельзя"))
        return None
    try:
        pwd.getpwnam(login)
    except KeyError:
        pass
    else:
        fail(_("Пользователь {0} на сервере уже есть").format(login))
        return None
    try:
        grp.getgrnam(login)
    except KeyError:
        return login
    fail(_("Имя {0} занято группой на сервере").format(login))
    return None


def screen_add():
    K_PROJ, K_LOOK, K_ROOT = _("доступ к проектам"), _("только осмотреться на сервере (без проектов)"), _("весь сервер — root")
    kind = choose(_("Что дать?"), [K_PROJ, K_LOOK, K_ROOT])
    if not kind:
        return
    if kind == K_ROOT:
        name = ask(_("Имя: "), _("кто это, например, Anna"))
        if not name:
            return
        name = clean(" ".join(name.split()), 60).lstrip("#-") or _("без имени")
        if any(e["name"].casefold() == name.casefold() for e in root_keys()):
            return fail(_("Имя {0} уже есть у другого ключа root").format(name))
        key, fp = ask_key()
        if not key:
            return
        if not confirm_code(_("{0} получит ПОЛНЫЙ root на сервере (ключ {1}…).").format(name, fp[:19])):
            return fail(_("Не подтверждено — ничего не изменено."))
        with lock():
            write_root_keys(root_keys() + [{"name": name, "key": key}])
        log(_("добавлен {0} (root) {1}").format(name, fp))
        box(_("✓ {0}: весь сервер, root").format(name), "", _("Пусть заходит так:"), "", f"  ssh root@{HOST}", color="42")
        return pause()

    allp, levels = projects(), {}
    if kind == K_PROJ and not allp:
        return fail(_("Проектов пока нет: kilt ищет проекты docker compose в папках {0}").format(", ".join(CLOSED)))
    login = ask_login()
    if not login:
        return
    DONE = _("✓ готово — дальше к ключу")
    while kind == K_PROJ:
        chosen = ", ".join(f"{n} ({P_LEVEL[l]})" for n, l in levels.items())
        left = [n for n in sorted(allp) if n not in levels]
        name = choose(f"{login}: " + (_("уже выбрано — {0}. Добавить ещё проект?").format(chosen) if levels
                                      else _("какой проект дать? (↑↓ и Enter)")), ([DONE] if levels else []) + left)
        if not name:
            if not levels or confirm(_("Выйти без сохранения?"), _("Выйти"), _("Вернуться")):
                return
            continue
        if name == DONE:
            break
        l = choose(_("{0} → {1}: какой доступ?").format(login, name), [P_LEVEL["read"], P_LEVEL["rw"]])
        if l == P_LEVEL["rw"] and not confirm(_("{0} Дать {1} root на {2}?").format(RW_WARNING, login, name), _("Дать")):
            continue
        if l:
            levels[name] = "rw" if l == P_LEVEL["rw"] else "read"
        if not [n for n in allp if n not in levels]:
            break
    key, fp = ask_key()
    if not key:
        return
    say(_("Настраиваю…"), "240")
    with lock():
        create_user(login, key)
        for name, l in levels.items():
            set_project(login, name, l, allp)
        refresh(allp, only=login)
    what = ", ".join(f"{n} — {P_LEVEL[l]}" for n, l in levels.items()) or _("без проектов, только осмотреться")
    log(_("добавлен {0}: {1} {2}").format(login, what, fp))
    tail = [_("Его проекты — в домашней папке: cd ~/") + next(iter(levels)),
            _("Контейнеры: kilt ps, kilt logs -f <сервис>") + (", kilt restart, kilt exec" if "rw" in levels.values() else "")] if levels else []
    box(f"✓ {login}: {what}", "", _("Пусть заходит так:"), "", f"  ssh {login}@{HOST}", "", *tail, color="42")
    pause()


def screen_root_person(e):
    pick = choose(_("{0} — весь сервер, root   ({1}…)").format(e['name'], e['fp'][:19]), [_("забрать доступ"), _("← назад")])
    if pick != _("забрать доступ"):
        return
    if len([x for x in root_keys() if not x["service"] and x["fp"] != e["fp"]]) == 0:
        return fail(_("Это последний ключ root — без него на сервер никто не зайдёт. Сначала добавь другой."))
    if not confirm(_("Забрать у {0} доступ к серверу?").format(e['name']), _("Забрать")):
        return
    with lock():
        write_root_keys([x for x in root_keys() if x["fp"] != e["fp"]])
    n = kick_fp(e["fp"])
    log(_("удалён {0} (root) {1}, закрыто сессий: {2}").format(e['name'], e['fp'], n))
    box(_("✓ {0}: ключ убран").format(e['name']) + (_(", закрыто открытых сессий: {0}").format(n) if n else ""), "",
        _("У него был root: он мог оставить себе другой вход (запасной ключ, задание cron, свою программу)."),
        _("Если расстались не по-хорошему — проверь сервер или переустанови его."), color="214")
    pause()


def screen_account(u):
    login = u["login"]
    while True:
        allp = projects()
        mine = user_projects(login, allp)
        items = [f"{n:<24} {P_LEVEL.get(mine.get(n), _('нет доступа'))}" for n in sorted(allp)]
        pick = choose(_("{0} — проекты (Enter — изменить)   ключ {1}…").format(login, (u['fp'] or _('нет'))[:19]),
                      [*items, _("заменить ключ"), _("удалить пользователя"), _("← назад")])
        if not pick or pick == _("← назад"):
            return
        if pick == _("удалить пользователя"):
            if confirm(_("Удалить {0} с сервера вместе с домашней папкой?").format(login), _("Удалить")):
                try:
                    delete_user(login)
                except RuntimeError as e:
                    return fail(_("Ошибка: {0}").format(e))
                say(_("✓ {0} удалён").format(login))
                time.sleep(1)
                return
            continue
        if pick == _("заменить ключ"):
            key, fp = ask_key()
            if key:
                with lock():
                    write_user_key(login, key, allp, mine)
                    closed = kill_user(login)
                u["key"], u["fp"] = key, fp
                log(_("{0}: новый ключ {1}").format(login, fp))
                if closed:
                    say(_("✓ Ключ заменён, старые сессии закрыты"))
                    time.sleep(1)
                else:
                    log(_("ВНИМАНИЕ: не удалось завершить все процессы {0}").format(login))
                    fail(_("Ключ заменён, но закрыть все старые сессии не удалось"))
            continue
        name = pick.split()[0]
        if name not in allp:
            continue
        l = choose(f"{login} → {name}", [_("нет доступа"), P_LEVEL["read"], P_LEVEL["rw"], _("← назад")])
        if not l or l == _("← назад"):
            continue
        level = {_("нет доступа"): None, P_LEVEL["read"]: "read", P_LEVEL["rw"]: "rw"}[l]
        if level == mine.get(name):
            continue
        if level == "rw" and not confirm(_("{0} Дать {1} root на {2}?").format(RW_WARNING, login, name), _("Дать")):
            continue
        say(_("Настраиваю…"), "240")
        try:
            set_project(login, name, level, allp)
        except RuntimeError as e:
            fail(_("Ошибка: {0}").format(e))
            continue
        say(f"✓ {login} → {name}: {l}")
        time.sleep(1)


def others():
    rows, managed = {}, {u["login"] for u in accounts()}
    unmanaged = sum(1 for raw, e in root_key_lines() if not e and raw.strip() and not raw.lstrip().startswith("#"))
    if unmanaged:
        rows["· " + _("root: ещё ключей не через это меню: {0} (с опциями или сертификаты)").format(unmanaged)] = \
            _("Эти строки в {0} kilt не меняет — их правят только вручную.").format(ROOT_KEYS)
    for p in pwd.getpwall():
        if p.pw_name == "root" or p.pw_name in managed or p.pw_uid < 1000 or not p.pw_shell.endswith("sh"):
            continue
        n = 0
        try:
            fd = os.open(os.path.join(p.pw_dir, ".ssh", "authorized_keys"), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as f:
                if stat.S_ISREG(os.fstat(fd).st_mode):
                    n = sum(1 for line in f.read(200000).decode("utf-8", "replace").splitlines() if fingerprint(line))
        except (OSError, UnicodeDecodeError):
            continue
        if n:
            groups = set(run("id", "-nG", p.pw_name, check=False).split())
            root_like = next((g for g in ROOT_GROUPS if g in groups), None)
            rights = _("группа {0} — то же, что root").format(root_like) if root_like else _("обычный")
            rows["· " + _("{0}: отдельная учётка, {1}, ключей {2}").format(p.pw_name, rights, n)] = \
                _("Это отдельная учётка, меню её не меняет.")
    return rows


def menu():
    ADD, QUIT, SEP = _("➕ Добавить человека"), _("Выход"), _("── не через это меню ──")
    while True:
        allp, rows = projects(), {}
        for e in root_keys():
            if not e["service"]:
                rows[_("{0:<23} весь сервер, root   {1}…").format(e['name'][:22], e['fp'][:19])] = ("root", e)
        for u in accounts():
            mine = user_projects(u["login"], allp)
            desc = ", ".join(f"{n} ({P_LEVEL[l]})" for n, l in mine.items()) or _("без проектов")
            rows[f"{u['login'][:22]:<23} {desc}"] = ("acc", u)
        extra = others()
        pick = choose(_("Доступ к серверу {0}").format(HOST), [ADD, *rows, *([SEP, *extra] if extra else []), QUIT])
        if pick is None or pick == QUIT:
            return
        try:
            if pick == ADD:
                screen_add()
            elif pick in rows:
                kind, obj = rows[pick]
                screen_root_person(obj) if kind == "root" else screen_account(obj)
            elif pick in extra:
                box(pick[2:], "", extra[pick], color="240")
                pause()
        except RuntimeError as e:
            fail(_("Ошибка: {0}").format(e))


# ---------------------------------------------------------------- установка
SSHD_BEGIN = "# >>> kilt: personal accounts (managed by `kilt setup`) >>>"   # маркеры в файле — не переводятся
SSHD_END = "# <<< kilt: end of personal accounts <<<"
SSHD_BLOCK = f"""{SSHD_BEGIN}
Match Group {GROUP_ALL}
    AuthorizedKeysFile {KEYS_DIR}/%u
    AllowTcpForwarding local
    AllowStreamLocalForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTunnel no
    GatewayPorts no
    PermitUserRC no
Match all
{SSHD_END}
"""
UNITS = {
    "kilt-sync.service": "[Unit]\nDescription=kilt: permissions, keys and network of personal accounts\n[Service]\nType=oneshot\nExecStart=/usr/local/bin/kilt sync\n",
    "kilt-sync.timer": "[Unit]\nDescription=kilt sync every 10 minutes\n[Timer]\nOnBootSec=2min\nOnUnitActiveSec=10min\n[Install]\nWantedBy=timers.target\n",
    "kilt-firewall.service": "[Unit]\nDescription=kilt: network rules and project views (before sshd)\nBefore=ssh.service sshd.service\n"
                               "[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/local/bin/kilt boot\n[Install]\nWantedBy=multi-user.target\n",
}


def sshd_config_with_block(old):
    start = old.find(SSHD_BEGIN)
    if start < 0:
        return old.rstrip("\n") + "\n\n" + SSHD_BLOCK
    end = old.find(SSHD_END, start)
    after = "" if end < 0 else old[end + len(SSHD_END):]
    return old[:start] + SSHD_BLOCK + (after[1:] if after.startswith("\n") else after)


def bind_block_works():
    # SocketBindDeny нужен systemd, собранный с BPF; без него systemd молча пропускает запрет
    return "+BPF_FRAMEWORK" in run("systemctl", "--version", check=False)


def setup():
    global CLOSED
    gid_of(GROUP_ALL)
    os.makedirs(ETC, mode=0o755, exist_ok=True)
    os.makedirs(KEYS_DIR, mode=0o755, exist_ok=True)
    if not os.path.exists(CONF):
        write_root_file(CONF, "{}\n", 0o644)
    if not os.path.exists(SETTINGS):
        closed = default_closed()
        if not closed:
            os.makedirs("/srv", mode=0o755, exist_ok=True)
            closed = ["/srv"]
        CLOSED = closed
        write_root_file(SETTINGS, json.dumps({"host": "", "closed": closed, "service_keys": [], "language": UI_LANG},
                                             ensure_ascii=False, indent=2) + "\n", 0o644)
        print(_("kilt: создан {0} — проверь адрес сервера и папки с проектами").format(SETTINGS))
    for path, mode in ((LOG, 0o600), (STATE, 0o600)):
        if os.path.exists(path):
            os.chmod(path, mode)
    os.makedirs(os.path.dirname(SYSCTL), mode=0o755, exist_ok=True)
    write_root_file(SYSCTL, "fs.protected_hardlinks = 1\nfs.protected_symlinks = 1\n", 0o644)
    if shutil.which("sysctl"):
        run("sysctl", "-p", SYSCTL, check=False)
    sudoers = "/etc/sudoers.d/kilt"
    write_root_file(sudoers + ".tmp", f"%{GROUP_ALL} ALL=(root) NOPASSWD: /usr/local/bin/kilt containers, /usr/local/bin/kilt containers *\n", 0o440)
    try:
        run("visudo", "-cf", sudoers + ".tmp")
    except RuntimeError:
        os.remove(sudoers + ".tmp")
        raise
    os.replace(sudoers + ".tmp", sudoers)
    write_root_file("/etc/security/limits.d/kilt.conf",
                    f"@{GROUP_ALL} hard nproc 256\n@{GROUP_ALL} hard nofile 4096\n@{GROUP_ALL} hard fsize 4194304\n@{GROUP_ALL} hard core 0\n", 0o644)
    cfg = "/etc/ssh/sshd_config"
    with open(cfg, encoding="utf-8", errors="surrogateescape", newline="") as f:
        old = f.read()
    new = sshd_config_with_block(old)
    if new != old:
        os.makedirs(BACKUPS, mode=0o700, exist_ok=True)
        shutil.copy2(cfg, f"{BACKUPS}/sshd_config-{datetime.datetime.now():%Y%m%d-%H%M%S}")
        write_root_file(cfg, new, 0o644)
        try:
            r = subprocess.run([shutil.which("sshd") or "/usr/sbin/sshd", "-t"], capture_output=True, text=True, timeout=60)
            err = (r.stderr or r.stdout).strip() if r.returncode else None
        except (OSError, subprocess.SubprocessError) as e:
            err = missing("sshd") if isinstance(e, FileNotFoundError) else str(e)
        if err is not None:
            write_root_file(cfg, old, 0o644)
            raise RuntimeError(_("sshd не принял новый блок настроек — возвращён прежний файл: {0}").format(clean(err, 400)))
        # ssh (Debian/Ubuntu) или sshd (RHEL); при сокет-активации служба не запущена и reload упал бы.
        for unit in ("ssh", "sshd"):
            if subprocess.run(["systemctl", "try-reload-or-restart", unit], capture_output=True).returncode == 0:
                break
    for name, body in UNITS.items():
        write_root_file(f"/etc/systemd/system/{name}", body, 0o644)
    run("systemctl", "daemon-reload")
    run("systemctl", "enable", "kilt-sync.timer", "kilt-firewall.service")
    run("systemctl", "start", "kilt-sync.timer")
    boot()
    if not bind_block_works():
        warn = _("Внимание: systemd на этом сервере собран без BPF, поэтому запрет слушать порты не работает. "
                 "Личные учётки смогут открыть порт выше 1024.")
        log(warn)
        print(warn)
    print(_("kilt: окружение установлено"))


def main():
    global HOST, CLOSED, SERVICE
    a = sys.argv[1:]
    os.umask(0o022)
    if os.geteuid() != 0:
        return as_user(a)
    HOST, CLOSED, SERVICE = load_settings()
    if a[:1] in (["help"], ["-h"], ["--help"]):
        print(_(__doc__) + "\n" + CONTAINER_HELP)
        return 0
    if a[:1] == ["containers"]:
        return container_cmd(a[1:])
    if a[:1] and a[0] in CONTAINER_CMDS:
        return container_cmd(a)
    if a[:1] == ["sync"]:
        return sync()
    if a[:1] == ["firewall"]:
        with lock():
            return firewall()
    if a[:1] == ["boot"]:
        return boot()
    if a[:1] == ["setup"]:
        return setup()
    if a:
        sys.exit(_(__doc__))
    if not shutil.which("gum"):
        sys.exit(_("Нужен gum: apt install gum"))
    menu()


if __name__ == "__main__":
    try:
        sys.exit(main() or 0)
    except KeyboardInterrupt:
        pass
    except RuntimeError as e:
        sys.exit(_("Ошибка: {0}").format(e))
    except FileNotFoundError as e:
        if e.filename and "/" not in str(e.filename):
            sys.exit(_("Ошибка: {0}").format(missing(e.filename)))
        sys.exit(_("Ошибка: {0}").format(_("файл не найден: {0}").format(clean(e.filename)) if e.filename else e))
    except PermissionError as e:
        sys.exit(_("Ошибка: нет прав — {0}").format(e))
