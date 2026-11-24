#!/usr/bin/python3 -I
"""Attacks from SECURITY.md against a real kilt install. Run only as root and only on a throwaway machine.

    sudo python3 tests/security.py
    sudo KILT_TEST_LANG=ru python3 tests/security.py
"""
import functools, importlib.machinery, importlib.util, json, os, platform, pwd, re, shutil, subprocess, sys, time

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
        for name, level in levels.items():
            k.set_project(login, name, level, allp)
        k.refresh(allp, only=login)


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
    rc, out = ssh("plain", bind)
    check("ports: a personal account cannot open a port on the server", "BOUND" not in out.splitlines(), out)
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
    finally:
        write(path, good)


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


def main():
    prepare()
    k = load_kilt()
    for login, levels in (("reader", {"demo": "read"}), ("rooter", {"demo": "rw"}), ("plain", {})):
        add_person(k, login, levels)
    p = functools.partial
    for step in (network, p(files, k), escape, p(race, k), p(names, k), bad_projects, ports, own_key, commands,
                 limits, settings, p(revoke, k)):
        try:
            step()
        except Exception as e:
            check(f"step {getattr(step, 'func', step).__name__} crashed", False, repr(e))
    fails = RESULTS.count("FAIL")
    print(f"\ntotal: {RESULTS.count('PASS')} PASS, {fails} FAIL, {RESULTS.count('SKIP')} SKIP")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
