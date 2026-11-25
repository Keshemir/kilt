#!/usr/bin/python3 -I
"""Checks the parts of kilt.py that need no root and no docker: file rights, key checks and project names.
It changes nothing on the machine; keys are made in a temporary folder.

    python3 tests/unit.py
"""
import importlib.machinery, importlib.util, os, shutil, subprocess, sys, tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = []


def load_kilt():
    loader = importlib.machinery.SourceFileLoader("kilt", os.path.join(REPO, "kilt.py"))
    spec = importlib.util.spec_from_loader("kilt", loader)
    k = importlib.util.module_from_spec(spec)
    loader.exec_module(k)
    return k


def check(name, ok, detail=""):
    status = "SKIP" if ok is None else "PASS" if ok else "FAIL"
    RESULTS.append(status)
    print(f"{status:4}  {name}" + (f"  -> {str(detail).strip()[:200]}" if detail and status != "PASS" else ""), flush=True)


def rights(k):
    cases = [
        ("a normal file: read for read, read and write for root on project", ("app/main.py", False, 0o644), {}, (4, 6)),
        ("a program and a folder also get x", ("app", True, 0o755), {}, (5, 7)),
        ("a secret by name is closed for read, read-only for root on project", (".env", False, 0o644), {}, (0, 4)),
        ("a key file is a secret", ("certs/site.key", False, 0o644), {}, (0, 4)),
        (".env.example is not a secret", (".env.example", False, 0o644), {}, (4, 6)),
        (".git/config is a secret", (".git/config", False, 0o644), {}, (0, 4)),
        ("nobody writes into .git", (".git/HEAD", False, 0o644), {}, (4, 4)),
        ("a secrets folder is closed for read", ("secrets", True, 0o755), {}, (0, 7)),
        ("a file in a secrets folder is a secret", ("secrets/key.txt", False, 0o644), {"in_secret": True}, (0, 4)),
        (".ssh is a secret folder", ("home/.ssh", True, 0o755), {}, (0, 7)),
        ("an owner-only file gets no kilt entries", ("private.txt", False, 0o600), {}, (None, None)),
        ("an owner-only folder gets no kilt entries", ("db", True, 0o700), {}, (None, None)),
        ("the project folder itself is never owner-only", ("", True, 0o700), {}, (5, 7)),
        ("a hidden path is closed for read only", ("docs/internal.md", False, 0o644), {"hide": ["docs/internal.md"]}, (0, 6)),
        ("hide matches a name in any folder", ("a/b/notes.txt", False, 0o644), {"hide": ["notes.txt"]}, (0, 6)),
        ("hide matches a pattern", ("logs/app.log", False, 0o644), {"hide": ["*.log"]}, (0, 6)),
        ('files "ro": root on project cannot write', ("app/main.py", False, 0o644), {"files_ro": True}, (4, 4)),
        ('files "ro": a folder is read-only too', ("app", True, 0o755), {"files_ro": True}, (5, 5)),
        ("node_modules is closed for the project's people", ("web/node_modules", True, 0o755), {}, (0, 0)),
        ("a folder from exclude is closed for the project's people", ("data", True, 0o755), {"exclude": ["data"]}, (0, 0)),
    ]
    for name, args, kw, want in cases:
        got = k.rights(*args, **kw)
        check(f"rights: {name}", got == want, f"{args} {kw}: {got}, expected {want}")
    walked = {"node_modules": k.not_walked("node_modules", True), "vendor": k.not_walked("a/vendor", True),
              "data": k.not_walked("data", True, ["data"]), "src": not k.not_walked("src", True),
              "project": not k.not_walked("", True, ["data"])}
    check("rights: kilt does not walk into node_modules, vendor and exclude folders, but walks the rest",
          all(walked.values()), walked)
    check("rights: a folder inside a secret folder stays secret for its files",
          k.is_secret("secrets/sub", True, k.is_secret("secrets", True)) and not k.is_secret("src", True))


def keys(k):
    if not shutil.which("ssh-keygen"):
        return check("keys: ssh-keygen is installed", None, "ssh-keygen not found")
    msg = {"broken": k._("Ключ повреждён: скопирован не целиком или с лишними символами."),
           "private": k._("Это ПРИВАТНЫЙ ключ — его нельзя никому отправлять. Пусть сделает новый "
                          "(ssh-keygen -t ed25519) и пришлёт строку из файла .pub."),
           "not_key": k._("Это не публичный SSH-ключ. Нужна одна строка, которая начинается с ssh-ed25519 или ssh-rsa.")}
    with tempfile.TemporaryDirectory() as tmp:
        made = {}
        for name, args in (("ed", ["-t", "ed25519"]), ("rsa1024", ["-t", "rsa", "-b", "1024"]),
                           ("rsa2048", ["-t", "rsa", "-b", "2048"])):
            path = os.path.join(tmp, name)
            r = subprocess.run(["ssh-keygen", "-q", *args, "-N", "", "-C", f"test {name}", "-f", path],
                               capture_output=True, text=True)
            if r.returncode == 0:
                made[name] = (open(path + ".pub").read().strip(), open(path).read())
        if "ed" not in made:
            return check("keys: ssh-keygen makes test keys", False, "could not make an ed25519 key")
        pub, private = made["ed"]
        real = subprocess.run(["ssh-keygen", "-l", "-E", "sha256", "-f", os.path.join(tmp, "ed.pub")],
                              capture_output=True, text=True).stdout.split()[1]
        key, fp = k.key_info(pub)
        check("keys: an ed25519 key is accepted, with the fingerprint that ssh-keygen shows",
              key == pub and fp == real and fp == k.fingerprint(pub), f"{key} {fp} {real}")
        key, fp = k.key_info("  " + pub.replace(" ", "   ") + "\r\n")
        check("keys: extra spaces and a Windows line end are removed", key == pub and fp == real, f"{key} {fp}")
        if "rsa2048" in made:
            key, fp = k.key_info(made["rsa2048"][0])
            check("keys: a 2048-bit RSA key is accepted", key == made["rsa2048"][0] and fp == k.fingerprint(key), fp)
        if "rsa1024" in made:
            key, err = k.key_info(made["rsa1024"][0])
            check("keys: a 1024-bit RSA key is refused as too short",
                  key is None and err == k._("RSA-ключ слишком короткий ({0} бит). Нужен ed25519 или RSA от 2048 бит.")
                  .format(1024), err)
        else:
            check("keys: a 1024-bit RSA key is refused as too short", None, "this ssh-keygen cannot make 1024-bit RSA keys")
        cases = [("a private key", private, "private"),
                 ("a private key pasted on one line", " ".join(private.split()), "private"),
                 ("a truncated key", pub[:60], "broken"),
                 ("an ed25519 key that says it is RSA", "ssh-rsa " + pub.split()[1], "broken"),
                 ("a text that is not a key", "hello", "not_key"),
                 ("a key with a control character", pub + "\x1b[2J", "not_key")]
        for name, line, want in cases:
            key, err = k.key_info(line)
            check(f"keys: {name} is refused with the right message", key is None and err == msg[want], err)


def names(k):
    a = k.project_names(["shop_v2", "shop-v2"], {})
    b = k.project_names(["shop-v2", "shop_v2"], {})
    check("project names: shop_v2 and shop-v2 get two different names, the same in any order",
          a == b and a.get("shop-v2") == "shop-v2" and len(a) == 2
          and next(n for n, c in a.items() if c == "shop_v2").startswith("shop-v2-"), f"{a} {b}")
    conf = {"other": {"compose": "demo"}}
    got = k.project_names(["other", "demo"], conf)
    check("project names: projects.json gives a name to a compose project, and the compose project of that name "
          "gets another one", got.get("other") == "demo" and len(got) == 2 and all(k.valid_name(n) for n in got), got)
    got = k.project_names(["My App!", "x" * 40], {})
    check("project names: any compose name becomes a valid project name", all(k.valid_name(n) for n in got), got)


def main():
    k = load_kilt()
    for step in (rights, keys, names):
        try:
            step(k)
        except Exception as e:
            check(f"step {step.__name__} crashed", False, repr(e))
    fails = RESULTS.count("FAIL")
    print(f"\ntotal: {RESULTS.count('PASS')} PASS, {fails} FAIL, {RESULTS.count('SKIP')} SKIP")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
