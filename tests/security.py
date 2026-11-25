#!/usr/bin/python3 -I
"""Attacks from SECURITY.md against a real kilt install. Run only as root and only on a throwaway machine.

    sudo python3 tests/security.py
    sudo KILT_TEST_LANG=ru python3 tests/security.py
"""
import functools, grp, importlib.machinery, importlib.util, json, os, platform, pwd, re, shutil, stat, struct, subprocess
import sys, time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = "/usr/local/bin/kilt"
WORK = "/root/kilt-test"
RESULTS = []
LANG = os.environ.get("KILT_TEST_LANG") or "en"
SAYS = {
    "ru": {"no_access": "нет доступа", "no_service": "Нет сервиса", "flags": "Флаги", "unknown": "Неизвестная команда",
           "unsupported": "не поддерживается", "rw_only": "только с правами"},
    "en": {"no_access": "no access", "no_service": "No service", "flags": "Flags are not supported",
           "unknown": "Unknown command", "unsupported": "is not supported", "rw_only": "works only with"},
}.get(LANG)
if SAYS is None:
    sys.exit(f"KILT_TEST_LANG must be en or ru, not {LANG!r}")


def run(*cmd, check=True, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if check and r.returncode:
        sys.exit(f"failed: {' '.join(cmd)}\n{r.stdout}{r.stderr}")
    return r


def check(name, ok, detail=""):
    status = "SKIP" if ok is None else "PASS" if ok else "FAIL"
    RESULTS.append(status)
    print(f"{status:4}  {name}" + (f"  -> {detail.strip()[:200]}" if detail and status != "PASS" else ""), flush=True)


def key(login):
    return f"{WORK}/{login}"


def ssh(login, cmd, extra=(), timeout=90, keyfile=None):
    r = subprocess.run(["ssh", "-i", keyfile or key(login), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                        "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=10",
                        *extra, f"{login}@127.0.0.1", cmd], capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout + r.stderr


def tcp_cmd(host, port):
    return f"timeout 4 bash -c 'exec 3<>/dev/tcp/{host}/{port}' 2>/dev/null && echo OPEN || echo CLOSED"


def root_can(host, port):
    return "OPEN" in run("bash", "-c", tcp_cmd(host, port), check=False).stdout


def user_can(login, host, port):
    return "OPEN" in ssh(login, tcp_cmd(host, port))[1]


def container_ip(name):
    return run("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", name).stdout.split()[0]


def write(path, text, mode=0o644):
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, mode)


def read_or_none(path):
    return open(path).read() if os.path.exists(path) else None


def restore(path, old):
    if old is not None:
        write(path, old)
    elif os.path.exists(path):
        os.remove(path)


def acl_groups(path, attr="system.posix_acl_access"):
    try:
        blob = os.getxattr(path, attr, follow_symlinks=False)
    except OSError:
        return set()
    entries = [struct.unpack_from("<HHI", blob, 4 + 8 * i) for i in range((len(blob) - 4) // 8)]
    return {gid for tag, _perm, gid in entries if tag == 0x08}


def has_acl(path):
    for attr in ("system.posix_acl_access", "system.posix_acl_default"):
        try:
            os.getxattr(path, attr, follow_symlinks=False)
            return True
        except OSError:
            pass
    return False


def strip_acl(path):
    for attr in ("system.posix_acl_access", "system.posix_acl_default"):
        try:
            os.removexattr(path, attr, follow_symlinks=False)
        except OSError:
            pass


def table_loaded():
    return run("nft", "list", "table", "inet", "kilt", check=False).returncode == 0


# ---------------------------------------------------------------- setup
def prepare():
    if os.geteuid() != 0:
        sys.exit("run this as root, on a throwaway machine")
    for prog in ("docker", "sshd", "ssh", "nft", "systemctl", "sudo"):
        if not shutil.which(prog) and not os.path.exists(f"/usr/sbin/{prog}"):
            sys.exit(f"program not found: {prog}")
    os.makedirs(WORK, mode=0o700, exist_ok=True)
    shutil.copy(f"{REPO}/kilt.py", BIN)
    os.chmod(BIN, 0o755)
    os.makedirs("/srv", exist_ok=True)
    os.makedirs("/etc/kilt", mode=0o755, exist_ok=True)
    write("/etc/kilt/config.json", json.dumps({"host": "127.0.0.1", "closed": ["/srv"], "service_keys": [], "language": LANG}))
    run("systemctl", "enable", "--now", "ssh", check=False)
    write("/etc/systemd/system/kilt-firewall.service", "[Unit]\nDescription=kilt before 0.2\n[Service]\nType=oneshot\n"
          "RemainAfterExit=yes\nExecStart=/bin/true\n[Install]\nWantedBy=multi-user.target\n")
    run("systemctl", "daemon-reload")
    run("systemctl", "enable", "kilt-firewall.service")
    run(BIN, "setup")

    projects = {
        "demo": ("services:\n"
                 "  app:\n    image: alpine:3.20\n    command: [\"sleep\", \"infinity\"]\n    volumes: [\"./shared:/shared\"]\n"
                 "  redis:\n    image: redis:7-alpine\n    ports: [\"127.0.0.1:16379:6379\"]\n"),
        "other": "services:\n  redis:\n    image: redis:7-alpine\n    ports: [\"127.0.0.1:16380:6379\"]\n",
    }
    for name, compose in projects.items():
        d = f"/srv/{name}"
        os.makedirs(f"{d}/shared", exist_ok=True)
        write(f"{d}/compose.yaml", compose)
        write(f"{d}/.env", f"SECRET={name}-secret\n")
        write(f"{d}/README.md", "hello\n")
        run("docker", "compose", "-p", name, "up", "-d", "--quiet-pull", cwd=d)
    os.makedirs("/srv/demo/.git", exist_ok=True)
    os.makedirs("/srv/demo/secrets", exist_ok=True)
    write("/srv/demo/.git/config", '[remote "origin"]\n\turl = https://deploy:FAKE-GIT-TOKEN@git.example.com/demo.git\n')
    write("/srv/demo/secrets/key.txt", "FAKE-FOLDER-SECRET\n")
    for _ in range(30):
        if root_can("127.0.0.1", 16379) and root_can("127.0.0.1", 16380):
            break
        time.sleep(1)


def load_kilt():
    loader = importlib.machinery.SourceFileLoader("kilt", BIN)
    spec = importlib.util.spec_from_loader("kilt", loader)
    k = importlib.util.module_from_spec(spec)
    loader.exec_module(k)
    k.HOST, k.CLOSED, k.SERVICE = k.load_settings()
    return k


def new_key(name):
    if not os.path.exists(key(name)):
        run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", key(name))
    return open(key(name) + ".pub").read().strip()


def add_person(k, login, levels):
    allp = k.projects()
    with k.lock():
        k.create_user(login, new_key(login))
        k.set_levels(login, levels, allp)


# ---------------------------------------------------------------- checks
def network():
    demo_redis, other_redis = container_ip("demo-redis-1"), container_ip("other-redis-1")
    check('network: "read" cannot reach its project\'s published port (127.0.0.1:16379)',
          not user_can("reader", "127.0.0.1", 16379))
    check('network: "read" cannot reach its project\'s database at the container address',
          not user_can("reader", demo_redis, 6379))
    check('network: "root on project" reaches its project\'s database (as it should)',
          user_can("rooter", demo_redis, 6379))
    check('network: "root on project" reaches its published port 127.0.0.1:16379 (as it should)',
          user_can("rooter", "127.0.0.1", 16379))
    check('network: "root on project" cannot reach another project at the container address',
          not user_can("rooter", other_redis, 6379))
    check('network: "root on project" cannot reach another project\'s published port (127.0.0.1:16380)',
          not user_can("rooter", "127.0.0.1", 16380))
    meta = root_can("169.254.169.254", 80)
    check("network: cloud metadata 169.254.169.254 is closed",
          None if not meta else not user_can("plain", "169.254.169.254", 80), "" if meta else "this machine has no metadata")
    net = root_can("1.1.1.1", 443)
    check("network: the internet is open (as it should be)",
          None if not net else user_can("plain", "1.1.1.1", 443), "" if net else "this machine has no internet")


def files(k):
    rc, out = ssh("reader", "cat ~/demo/README.md")
    check('files: "read" reads project files', rc == 0 and "hello" in out, out)
    rc, out = ssh("reader", "cat ~/demo/.env")
    check('files: "read" cannot read .env', rc != 0 and "secret" not in out, out)
    rc, out = ssh("reader", "cat ~/demo/.git/config")
    check('files: "read" cannot read .git/config', rc != 0 and "FAKE-GIT-TOKEN" not in out, out)
    rc, out = ssh("reader", "cat ~/demo/secrets/key.txt")
    check('files: "read" cannot read files in a "secrets" folder', rc != 0 and "FAKE-FOLDER-SECRET" not in out, out)
    rc, out = ssh("reader", "touch ~/demo/reader-was-here")
    check('files: "read" cannot change project files', rc != 0, out)
    rc, out = ssh("rooter", "cat ~/demo/.env && touch ~/demo/rooter-was-here")
    check('files: "root on project" reads .env and writes to the project', rc == 0 and "demo-secret" in out, out)
    rc, out = ssh("rooter", "cat ~/demo/.git/config ~/demo/secrets/key.txt")
    check('files: "root on project" reads .git/config and the "secrets" folder',
          rc == 0 and "FAKE-GIT-TOKEN" in out and "FAKE-FOLDER-SECRET" in out, out)
    rc, out = ssh("rooter", "ls /srv/demo")
    check("files: the real project path is closed, only the view is open", rc != 0, out)
    rc, out = ssh("plain", "ls /srv; cat /srv/demo/README.md")
    check("files: without projects, /srv is fully closed", "hello" not in out and rc != 0, out)
    rc, out = ssh("plain", "ls /run/kilt/view/demo/m; cat /run/kilt/view/demo/m/README.md /run/kilt/view/demo/m/.env")
    check("files: a person without the project cannot enter it through its view", "hello" not in out and "secret" not in out, out)
    write("/srv/demo/fresh-notes.txt", "NEW-NOTE-TEXT\n")
    write("/srv/demo/fresh.env", "SECRET=NEW-SECRET-VALUE\n")
    rc, out = ssh("reader", "cat ~/demo/fresh-notes.txt ~/demo/fresh.env")
    check('files: new files are closed for "read" until the sync', "NEW-" not in out, out)
    k.sync()
    rc, out = ssh("reader", "cat ~/demo/fresh-notes.txt; cat ~/demo/fresh.env")
    check("files: after the sync, the normal file is open and the secret is not",
          "NEW-NOTE-TEXT" in out and "NEW-SECRET-VALUE" not in out, out)


def escape():
    name = "container to server: a setuid file from a shared folder does not give root"
    rc, out = ssh("rooter", "cp /usr/bin/python3 ~/demo/shared/py && kilt exec app chown 0:0 /shared/py "
                            "&& kilt exec app chmod 4755 /shared/py")
    st = os.stat("/srv/demo/shared/py") if os.path.exists("/srv/demo/shared/py") else None
    if not (st and st.st_uid == 0 and st.st_mode & 0o4000):
        check(name, None, f"could not prepare the file: {out}")
    else:
        rc, out = ssh("rooter", "~/demo/shared/py -c 'import os; print(\"EUID\", os.geteuid())'")
        euid = re.search(r"EUID (\d+)", out)
        if not euid:
            check(name, None, f"the program did not run: {out}")
        else:
            check(name, euid.group(1) != "0", out)
    name = "container to server: a device file from a shared folder cannot be opened"
    rc, out = ssh("rooter", "kilt exec app mknod /shared/null c 1 3")
    if not os.path.exists("/srv/demo/shared/null"):
        check(name, None, f"mknod did not work: {out}")
    else:
        rc, out = ssh("rooter", "head -c1 ~/demo/shared/null; echo rc=$?")
        check(name, "rc=0" not in out, out)


SWAPPER = r"""
import ctypes, os, platform, time
libc = ctypes.CDLL(None, use_errno=True)
nr = {"x86_64": 316, "aarch64": 276}[platform.machine()]
os.chdir(os.path.expanduser("~/demo/race"))
end, n = time.time() + %d, 0
while time.time() < end:
    libc.syscall(nr, -100, b"a", -100, b"b", 2)   # renameat2(AT_FDCWD, a, AT_FDCWD, b, RENAME_EXCHANGE)
    n += 1
print("SWAPS", n)
"""


def race(k, seconds=20):
    name = "race with file rights: a root folder gets no rights"
    target = "/root/kilt-race-target"
    os.makedirs(target, mode=0o700, exist_ok=True)
    write(f"{target}/secret", "root only\n", 0o600)
    if platform.machine() not in ("x86_64", "aarch64"):
        return check(name, None, f"no renameat2 number for {platform.machine()}")
    rc, out = ssh("rooter", f"rm -rf ~/demo/race && mkdir -p ~/demo/race/a && ln -s {target} ~/demo/race/b")
    if rc != 0:
        return check(name, None, f"could not make the folder and the link: {out}")
    swapper = subprocess.Popen(["ssh", "-i", key("rooter"), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                                "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "rooter@127.0.0.1",
                                "python3 -"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True)
    swapper.stdin.write(SWAPPER % seconds)
    swapper.stdin.close()
    runs, end = 0, time.time() + seconds
    try:
        while time.time() < end:
            k.sync()
            runs += 1
    finally:
        try:
            swapper.wait(timeout=seconds + 60)
        except subprocess.TimeoutExpired:
            swapper.kill()
            swapper.wait()
    out = swapper.stdout.read().strip()
    swaps = re.search(r"SWAPS (\d+)", out)
    swaps = int(swaps.group(1)) if swaps else 0
    leaked = []
    for path in (target, f"{target}/secret"):
        for attr in ("system.posix_acl_access", "system.posix_acl_default"):
            try:
                os.getxattr(path, attr, follow_symlinks=False)
                leaked.append(f"{path} {attr}")
            except OSError:
                pass
    mode = os.stat(target).st_mode & 0o777
    if leaked or mode != 0o700:
        check(name, False, f"{leaked} {oct(mode)}; swaps: {swaps}, sync runs: {runs}; {out}")
    elif not swaps:
        check(name, None, f"the swapper did not run: {out}")
    else:
        check(name, True)


def names(k):
    path = "/etc/kilt/projects.json"
    old = read_or_none(path)
    try:
        write(path, json.dumps({"other": {"compose": "demo"}}))
        allp = k.projects()
        mixed = [n for n, p in allp.items() if p["compose"] == "other" and n == "other"]
        own = allp.get("other", {})
        check("project names: a found compose project does not take a name from projects.json and is not merged with it",
              not mixed and own.get("compose") == "demo" and set(own.get("services", {})) == {"app", "redis"},
              json.dumps({n: [p["compose"], sorted(p["services"])] for n, p in allp.items()}))
    finally:
        restore(path, old)


def bad_projects():
    path = "/etc/kilt/projects.json"
    old = read_or_none(path)
    try:
        write(path, json.dumps({"demo": {"hide": 5}}))
        r = run(BIN, "sync", check=False)
        out = r.stdout + r.stderr
        check('settings: projects.json with "hide": 5 stops kilt sync with an error message, not a traceback',
              r.returncode != 0 and out.strip() != "" and "Traceback" not in out, out)
        write(path, old if old is not None else "{}\n", 0o666)
        r = run(BIN, "sync", check=False)
        check("settings: a projects.json that everyone can write to is refused", r.returncode != 0, r.stdout + r.stderr)
    finally:
        restore(path, old)
        run(BIN, "sync", check=False)


def ports():
    rc, out = ssh("plain", "echo '* * * * * true' | crontab -")
    check("cron is blocked for personal accounts", None if "not found" in out else rc != 0, out)
    bind = "python3 -c \"import socket; s=socket.socket(); s.bind(('0.0.0.0', 3010)); s.listen(); print('BOUND')\""
    version = run("systemctl", "--version", check=False).stdout
    rc, out = ssh("plain", "grep -o 'user-[0-9]*.slice' /proc/self/cgroup; " + bind)
    if "+BPF_FRAMEWORK" not in version:
        check("ports: a personal account cannot open a port on the server", None,
              "systemd is built without BPF_FRAMEWORK, kilt setup warns about it")
    else:
        check("ports: a personal account cannot open a port on the server", "BOUND" not in out.splitlines(),
              out + " | " + version.splitlines()[0])
    rc, out = ssh("plain", "true", extra=("-o", "ExitOnForwardFailure=yes", "-R", "3011:127.0.0.1:22"))
    check("ports: ssh -R is not allowed", rc != 0, out)


def own_key():
    pub = new_key("extra")
    ssh("plain", f"mkdir -p ~/.ssh && echo '{pub}' >> ~/.ssh/authorized_keys")
    rc, out = ssh("plain", "echo IN", keyfile=key("extra"))
    check("keys: a key in ~/.ssh/authorized_keys does not work", "IN" not in out, out)


def commands():
    cases = [
        ("rooter", "kilt -p other ps", "no_access"),
        ("rooter", "kilt -p ../../etc ps", "no_access"),
        ("rooter", "kilt exec 'app;id'", "no_service"),
        ("rooter", "kilt restart --privileged app", "flags"),
        ("rooter", "kilt run app", "unknown"),
        ("rooter", "kilt logs --since '$(id)' redis", "unsupported"),
        ("reader", "kilt exec app id", "rw_only"),
        ("reader", "kilt restart app", "rw_only"),
        ("plain", "kilt -p demo ps", "no_access"),
    ]
    for login, cmd, what in cases:
        expect = SAYS[what]
        rc, out = ssh(login, cmd)
        check(f"commands: {login}: {cmd} is refused", rc != 0 and expect in out and "uid=" not in out, out)
    rc, out = ssh("rooter", "kilt ps")
    check("commands: kilt ps shows the project's containers", rc == 0 and "app" in out and "redis" in out, out)
    rc, out = ssh("reader", "cd ~/demo && kilt logs --tail 1 redis")
    check('commands: "read" can see the logs', rc == 0, out)


def limits():
    uid = pwd.getpwnam("plain").pw_uid
    r = run("systemctl", "show", f"user-{uid}.slice", "-p", "TasksMax", "-p", "MemoryMax", check=False)
    vals = dict(line.split("=", 1) for line in r.stdout.splitlines() if "=" in line)
    check("limits: 256 processes and 1 GB of memory for each account",
          vals.get("TasksMax") == "256" and vals.get("MemoryMax") == "1073741824", r.stdout + r.stderr)


def settings():
    path = "/etc/kilt/config.json"
    good = open(path).read()
    try:
        for bad in (["/"], ["/home"], ["/usr/local"], ["/var"]):
            write(path, json.dumps({"closed": bad}))
            r = run(BIN, "sync", check=False)
            check(f"settings: {bad[0]} as a project folder is refused", r.returncode != 0, r.stdout + r.stderr)
        write(path, good, 0o666)
        r = run(BIN, "sync", check=False)
        check("settings: a config file that everyone can write to is refused", r.returncode != 0, r.stdout + r.stderr)
        run("nft", "delete", "table", "inet", "kilt", check=False)
        r = run(BIN, "boot", check=False)
        check("firewall: with a broken config.json, kilt boot still loads the base rules and exits with an error",
              r.returncode != 0 and table_loaded(), r.stdout + r.stderr)
    finally:
        write(path, good)
        run(BIN, "firewall", check=False)


def revoke(k):
    ssh("rooter", "nohup setsid sh -c 'while :; do (sleep 300 &); sleep 0.2; done' >/dev/null 2>&1 &")
    time.sleep(2)
    uid = pwd.getpwnam("rooter").pw_uid
    k.delete_user("rooter")
    alive = run("pgrep", "-u", str(uid), check=False).stdout.split()
    check("removing access: no processes are left after the person is deleted", not alive, f"still running: {alive}")
    rc, out = ssh("rooter", "echo IN")
    check("removing access: a deleted person cannot log in", "IN" not in out, out)
    add_person(k, "tmp2", {})
    check("removing access: a user ID is not given out again", pwd.getpwnam("tmp2").pw_uid != uid)


def private_files(k):
    write("/srv/demo/private.txt", "PRIVATE-TEXT\n", 0o600)
    write("/srv/demo/acme.json", '{"token": "ACME-TEXT"}\n', 0o644)
    inside = ["/srv/demo/node_modules/lib", "/srv/demo/node_modules/lib/index.js", "/srv/demo/data/big.bin"]
    os.makedirs("/srv/demo/node_modules/lib", exist_ok=True)
    os.makedirs("/srv/demo/data", exist_ok=True)
    write("/srv/demo/node_modules/lib/index.js", "module.exports = 1\n")
    write("/srv/demo/data/big.bin", "DATA\n")
    for path in inside:
        strip_acl(path)
    path = "/etc/kilt/projects.json"
    old = read_or_none(path)
    try:
        write(path, json.dumps({"demo": {"exclude": ["data"]}}))
        k.sync()
        closed = {login: ssh(login, "echo IN; cat ~/demo/data/big.bin; cat ~/demo/node_modules/lib/index.js")
                  for login in ("reader", "rooter")}
    finally:
        restore(path, old)
    mode = stat.S_IMODE(os.stat("/srv/demo/private.txt").st_mode)
    rc, out = ssh("reader", "cat ~/demo/private.txt")
    check('files: a file only for its owner (600) stays 600 after the sync, and "read" cannot read it',
          mode == 0o600 and rc != 0 and "PRIVATE-TEXT" not in out, f"mode {oct(mode)}: {out}")
    rc, out = ssh("reader", "cat ~/demo/acme.json")
    check('files: "read" cannot read acme.json', rc != 0 and "ACME-TEXT" not in out, out)
    touched = [p for p in inside if has_acl(p)]
    check("files: kilt does not walk node_modules and folders from exclude", not touched, f"ACL on: {touched}")
    check('files: "read" and "root on project" cannot open world-readable files in node_modules and in exclude folders',
          all("IN" in out and "DATA" not in out and "module.exports" not in out for _rc, out in closed.values()),
          json.dumps(closed))
    home = pwd.getpwnam("reader").pw_dir
    check("files: kilt does not write safe.directory = * into ~/.gitconfig", not os.path.exists(f"{home}/.gitconfig"))


def naming(k):
    for d in ("/srv/shop-a", "/srv/shop-b"):
        os.makedirs(d, exist_ok=True)
    lines = ["shop_v2|/srv/shop-a|web|shop_v2-web-1|aaa111", "shop-v2|/srv/shop-b|web|shop-v2-web-1|bbb222"]
    real, seen = k.run, []
    try:
        for order in (lines, lines[::-1]):
            k.run = lambda *cmd, order=order, **kw: ("\n".join(order) + "\n" if cmd[:2] == ("docker", "ps")
                                                     else real(*cmd, **kw))
            seen.append({p["compose"]: n for n, p in k.projects().items() if p["compose"] in ("shop_v2", "shop-v2")})
    finally:
        k.run = real
        for d in ("/srv/shop-a", "/srv/shop-b"):
            os.rmdir(d)
    a = seen[0]
    check("project names: shop_v2 and shop-v2 get two different names, the same in any docker ps order",
          len(a) == 2 and a == seen[1] and a.get("shop-v2") == "shop-v2" and a.get("shop_v2", "").startswith("shop-v2-"),
          json.dumps(seen))


def setid(k):
    home = pwd.getpwnam("rooter").pw_dir
    steps = (("p-demo-rw", "read", f"{home}/b2", "touch ~/demo/setgid-was-here", "/srv/demo/setgid-was-here",
              '"root on project" -> "read": a setgid file of p-demo-rw loses the bit and does not give write access'),
             ("p-demo", None, f"{home}/b", "ls /run/kilt/view/demo/m", None,
              'project removed: a setgid file of p-demo loses the bit and does not open the project'))
    try:
        for group, level, path, use, made, name in steps:
            rc, out = ssh("rooter", f"cp /bin/bash ~/{os.path.basename(path)} && chgrp {group} {path} && chmod 2755 {path} "
                                    f"&& {path} -p -c 'id -gn'")
            if group not in out or not os.stat(path).st_mode & 0o2000:
                check(f"removing access: {name}", None, f"setgid does not work here: {out}")
                continue
            k.set_levels("rooter", {"demo": level}, k.projects())
            rc, out = ssh("rooter", f"echo LOGGED-IN; {path} -p -c '{use}'")
            mode = os.stat(path).st_mode
            used = (made and os.path.exists(made)) or (not made and rc == 0)
            check(f"removing access: {name}", "LOGGED-IN" in out and not mode & 0o6000 and not used,
                  f"mode {oct(mode)}, rc {rc}: {out}")
    finally:
        k.set_levels("rooter", {"demo": "rw"}, k.projects())


def subids(k):
    paths = [p for p in ("/etc/subuid", "/etc/subgid") if os.path.exists(p)]
    name = "user namespaces: no kilt account has a line in /etc/subuid or /etc/subgid"
    if not paths:
        return check(name, None, "this machine has no /etc/subuid or /etc/subgid")
    uid = pwd.getpwnam("plain").pw_uid
    for path in paths:
        with open(path, "a") as f:
            f.write(f"plain:300000:65536\n{uid}:370000:65536\nnot-kilt:400000:65536\n")
    k.sync()
    logins = {u["login"] for u in k.accounts()}
    bad, kept = [], True
    for path in paths:
        lines = open(path).read().splitlines()
        kept = kept and "not-kilt:400000:65536" in lines
        bad += [f"{path}: {l}" for l in lines if l.split(":")[0] in logins
                or (l.split(":")[0].isdigit() and 70000 <= int(l.split(":")[0]) <= 79999)]
        write(path, "".join(l + "\n" for l in lines if l != "not-kilt:400000:65536"))
    check(name + " (other lines stay)", not bad and kept, f"{bad}, other line kept: {kept}")


def units():
    enabled = run("systemctl", "is-enabled", "kilt-boot.service", check=False).stdout.strip()
    active = run("systemctl", "is-active", "kilt-boot.service", check=False).stdout.strip()
    old = os.path.exists("/etc/systemd/system/kilt-firewall.service") \
        or os.path.lexists("/etc/systemd/system/multi-user.target.wants/kilt-firewall.service")
    check("units: kilt-boot.service is enabled and active, the old kilt-firewall.service is removed",
          enabled == "enabled" and active == "active" and not old, f"{enabled} {active} old unit: {old}")
    conf = open("/etc/ssh/sshd_config").read()
    dropin = read_or_none("/etc/ssh/sshd_config.d/00-kilt.conf") or ""
    if re.search(r"(?im)^\s*include\s+/etc/ssh/sshd_config\.d/\*\.conf", conf):
        check("sshd: the kilt block is in sshd_config.d/00-kilt.conf and ends with Match all",
              "kilt" not in conf and "Match Group kilt" in dropin and dropin.rstrip().endswith("Match all"), dropin)
    else:
        check("sshd: the kilt block is at the end of sshd_config", "Match Group kilt" in conf and not dropin, conf[-400:])
    rotate = read_or_none("/etc/logrotate.d/kilt") or ""
    check("log: /etc/logrotate.d/kilt rotates /var/log/kilt.log", "/var/log/kilt.log" in rotate and "rotate 8" in rotate, rotate)
    deny = (read_or_none("/etc/at.deny") or "").split()
    check("at is blocked for personal accounts", {"reader", "rooter", "plain"} <= set(deny), " ".join(deny))
    r, h = run(BIN, "--version", check=False), run(BIN, "help", check=False)
    check("kilt --version prints the version, kilt help shows it too",
          r.returncode == 0 and re.fullmatch(r"kilt \d+\.\d+\.\d+", r.stdout.strip()) and r.stdout.strip() in h.stdout,
          r.stdout + r.stderr)
    lines = [l for l in (read_or_none("/var/log/kilt.log") or "").splitlines()
             if re.search(r"\] sync: \d+\.\d \S+, \D+: \d+, \D+: \d+, \D+: \d+$", l)]
    check("log: every sync writes one line with its time and the numbers of files seen, changed and errors",
          bool(lines), (read_or_none("/var/log/kilt.log") or "")[-400:])


def boot_offline(k):
    real, calls = k.run, []

    def no_docker(*cmd, **kw):
        if cmd[:1] == ("docker",):
            calls.append(" ".join(cmd[:2]))
            raise RuntimeError("docker is off in this test")
        return real(*cmd, **kw)

    run("nft", "delete", "table", "inet", "kilt", check=False)
    k.drop_view("demo")
    k.run = no_docker
    try:
        rc = k.boot()
    finally:
        k.run = real
    view = k.view_ok("demo", {"dir": "/srv/demo"})
    loaded = table_loaded()
    k.firewall()
    check("boot: without docker, kilt boot loads the base firewall and mounts the views from state.json",
          rc == 0 and not calls and loaded and view, f"rc {rc}, docker calls {calls}, table {loaded}, view {view}")


def nft_restart():
    d = "/etc/systemd/system/nftables.service.d"
    os.makedirs(d, exist_ok=True)
    write(f"{d}/kilt-test.conf", "[Service]\nExecStart=\nExecStart=/usr/sbin/nft delete table inet kilt\n"
                                 "ExecReload=\nExecReload=/usr/sbin/nft delete table inet kilt\nExecStop=\n")
    run("systemctl", "daemon-reload")
    try:
        for action in ("restart", "reload"):
            r = run("systemctl", action, "nftables.service", check=False)
            for _ in range(20):
                if table_loaded():
                    break
                time.sleep(0.5)
            check(f"firewall: systemctl {action} nftables (which removes the kilt table) brings the kilt rules back",
                  r.returncode == 0 and table_loaded(), r.stdout + r.stderr)
    finally:
        os.remove(f"{d}/kilt-test.conf")
        run("systemctl", "daemon-reload")


def uninstall():
    gids = {g.gr_gid for g in grp.getgrall() if g.gr_name == "kilt" or g.gr_name.startswith("p-")}
    r = run(BIN, "uninstall", "--remove-users", "--yes", "--purge", check=False)
    out = r.stdout + r.stderr
    check("uninstall: kilt uninstall --remove-users --yes --purge finishes without errors", r.returncode == 0, out)
    check("uninstall: no nft table inet kilt", not table_loaded())
    left = [u for u in ("kilt-sync.timer", "kilt-sync.service", "kilt-boot.service", "kilt-firewall.service")
            if os.path.lexists(f"/etc/systemd/system/{u}")]
    check("uninstall: no kilt units", not left, str(left))
    files = [f for f in ("/etc/sudoers.d/kilt", "/etc/security/limits.d/kilt.conf", "/etc/sysctl.d/90-kilt.conf",
                         "/etc/logrotate.d/kilt", "/etc/ssh/sshd_config.d/00-kilt.conf", "/etc/kilt", "/run/kilt")
             if os.path.lexists(f)]
    check("uninstall: no sudo rule, limits, sysctl, logrotate, sshd drop-in, /etc/kilt, /run/kilt", not files, str(files))
    conf = open("/etc/ssh/sshd_config").read()
    test = run(shutil.which("sshd") or "/usr/sbin/sshd", "-t", check=False)
    check("uninstall: sshd_config has no kilt block and sshd -t passes", "kilt" not in conf and test.returncode == 0,
          test.stderr)
    users = [p.pw_name for p in pwd.getpwall() if 70000 <= p.pw_uid <= 79999]
    groups = [g.gr_name for g in grp.getgrall() if g.gr_name == "kilt" or g.gr_name.startswith("p-")]
    check("uninstall: no users in the UID range 70000-79999, no group kilt or p-*", not users and not groups,
          f"{users} {groups}")
    acl = {p: sorted(gids & (acl_groups(p) | acl_groups(p, "system.posix_acl_default")))
           for p in ("/srv", "/srv/demo", "/srv/demo/README.md", "/srv/demo/.env")}
    check("uninstall: no kilt entries in the ACLs of /srv and /srv/demo", not any(acl.values()), json.dumps(acl))
    check("uninstall: project files stay", os.path.exists("/srv/demo/README.md") and os.path.exists("/srv/demo/.env"))


def main():
    prepare()
    k = load_kilt()
    for login, levels in (("reader", {"demo": "read"}), ("rooter", {"demo": "rw"}), ("plain", {})):
        add_person(k, login, levels)
    p = functools.partial
    for step in (network, p(files, k), p(private_files, k), escape, p(race, k), p(names, k), p(naming, k), bad_projects,
                 ports, own_key, commands, p(setid, k), p(subids, k), limits, units, settings, p(boot_offline, k),
                 p(revoke, k), nft_restart, uninstall):
        try:
            step()
        except Exception as e:
            check(f"step {getattr(step, 'func', step).__name__} crashed", False, repr(e))
    fails = RESULTS.count("FAIL")
    print(f"\ntotal: {RESULTS.count('PASS')} PASS, {fails} FAIL, {RESULTS.count('SKIP')} SKIP")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
