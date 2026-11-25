# Security

kilt runs as root and gives people shell access. Its job is to keep a person with a personal account inside what the menu gave them. This file says what that means, what kilt does not cover, and how kilt is tested.

## How to report a problem

Please do not open a public issue. Use GitHub's private reporting for this repository (Security → Report a vulnerability). Write the kilt commit, the system, and the steps to repeat the problem.

## What kilt protects against

These protections are for people with **read** access or with no projects. A person with such a personal account cannot:

- get root on the server, or rights on folders outside their projects;
- read other projects' files, or the secrets of their own project;
- connect to services on the server or in private networks (databases, Redis, mail servers, cloud metadata), except the DNS servers from `/etc/resolv.conf`;
- stop the server by using all processes, memory or CPU;
- stay after you remove them: with cron or `at`, with processes that keep running, with a second key, with a user ID that is given out again, with a setuid or setgid copy of a program, or with a user namespace that drops the `kilt` group;
- take ports that the web proxy or other services use;
- misuse container commands with flags, extra commands or another project's name;
- block kilt: a person cannot stop kilt while it holds its lock, and every command that kilt runs has a time limit.

**Root on project** is about trust. kilt gives such a person the same limits, and opens only the services of their own projects. But this person is root inside the project's containers and can change its files. A skilled person can use this to get root on the server, and then none of the rules above hold. See the next section.

## What kilt does not protect against

- **root.** Anyone with a root key can undo everything. Removing their key does not prove they are gone.
- **"root on project".** It means root inside the project's containers and the right to change its files. From there, a skilled person can get root on the server. Also, if an admin or a deploy later runs a script that this person changed, it runs with the admin's rights. Give this level only to people you trust.
- **secrets in files with normal names.** kilt finds secrets by name (`.env`, `*.key`, `secret`, `token`, `acme.json`, `.pgpass`, `.netrc`, `.npmrc`, `.envrc`, `*.tfstate`, `.git/config`, folders like `secrets` or `.ssh`…). Add other files to the project's `hide` list.
- **processes inside containers.** A process that a person starts with `kilt exec` runs in the container, not under their user ID. It keeps running after you remove the person. Restart the container if you need to be sure.
- **other users' processes.** `/proc` is not hidden. People see the processes of other users, with their command lines.
- **sshd settings that kilt does not own.** `AllowUsers` or `AllowGroups` can lock personal accounts out (`kilt setup` warns about it). A file in `/etc/ssh/sshd_config.d/` that sorts before `00-kilt.conf` and has its own `Match` for the same users wins over kilt.
- **container addresses that move.** If containers are recreated without kilt, a container address can go to another project. kilt updates the network rules at the next sync (up to 10 minutes) and every time a person restarts a container with kilt.
- **disk space.** There are no quotas.
- **listening ports on systems where systemd is built without BPF.** kilt blocks listening ports with systemd's `SocketBindDeny`. Without BPF support in systemd this setting does nothing, so people can open ports above 1024. `kilt setup` warns about it.
- **a new public address on the server** for up to 10 minutes. This happens only on kernels without `nft_fib_inet`, where kilt uses a list of addresses. Private networks are always blocked.
- **the rest of the server.** kilt does not fix files that everyone can read outside the project folders, services without passwords, an old kernel, or users made without kilt.

## What is done in the code

| Risk | What kilt does |
|---|---|
| Race while setting file rights (the classic `setfacl -R` problem with links) | kilt opens each file once with `O_NOFOLLOW` and sets rights on the open file |
| A hard link in a project folder to a file outside it, so that sync gives rights on that file | `kilt setup` turns on `fs.protected_hardlinks` and `fs.protected_symlinks` in `/etc/sysctl.d/90-kilt.conf`: a person cannot make a hard link to a file that they do not own |
| Escape from a container to the server through a shared folder (setuid file, device file) | people see projects only through mounts with `nosuid,nodev`; the real path is closed |
| A container that mounts `docker.sock` or runs privileged, or a shared folder without `nosuid` or `nodev` | kilt writes a warning to its log: with **root on project**, such a project gives an easy way to root on the server |
| A shell can connect to anything on the server or in private networks | nftables rules for the user IDs of personal accounts; only the DNS servers from `/etc/resolv.conf` are open; the full rules also block the subnets of all docker networks (IPv4 and IPv6) and `64:ff9b::/96` |
| No firewall after a reboot, a broken settings file, docker that does not answer, or `flush ruleset` | `kilt-boot.service` runs before sshd and needs neither docker nor the settings files: it loads a set of rules that only blocks. It runs again when `nftables.service` restarts or reloads. If kilt cannot build the full rules, the block-only set is loaded. `kilt boot`, `kilt sync` and `kilt setup` fail if the table `inet kilt` is missing |
| Using all resources | systemd limits for each account, `limits.d`, `SocketBindDeny=any` |
| Staying after removal | cron and `at` are blocked; all processes are stopped at once by the kernel; user IDs are never given out twice; crontab and temporary files are deleted |
| Keeping a project's group with a setuid or setgid file after access is reduced or removed | for a moment login is closed, the person's processes are stopped, and setuid and setgid bits are removed from their own files in their home folder, `/tmp`, `/var/tmp` and `/dev/shm`; every file is opened with `O_NOFOLLOW`, checked with `fstat` and changed through the open file |
| Dropping the `kilt` group in a user namespace (with ranges from `/etc/subuid` and `/etc/subgid`), so that the block on the project folders does not apply | kilt removes the lines of personal accounts from `/etc/subuid` and `/etc/subgid` when it creates a person and at every sync |
| Holding kilt's lock, so that sync never runs | while kilt holds the lock for a personal account, Ctrl+Z, Ctrl+C and a lost connection do not stop it; every command that kilt runs has a time limit; kilt waits for the lock only for a limited time |
| Changing keys, or logging in another way | keys are in `/etc/kilt/keys` and belong to root; sshd reads keys only from there; for the group `kilt` sshd turns off `AuthorizedKeysCommand`, `TrustedUserCAKeys`, passwords and keyboard-interactive login |
| Opening a project through its folder under `/run/kilt/view` without access | the entrance folder belongs to the project's group, mode 750 |
| A new secret file is readable before sync | people with **read** cannot open new files until the next sync; the sync then opens normal files and keeps secrets closed |
| Tokens in `.git/config`, files in folders like `secrets` or `.ssh` | they are treated as secrets: **read** cannot open them |
| A published port is open on every server address | kilt allows only the address and port that docker published |
| Two compose projects end up under one name, or access moves to another project after containers are created again | a found project keeps its compose name only if it is a valid name; otherwise its name is the cleaned name plus 5 characters of its hash, so the name never depends on the order of `docker ps`; a found project never takes a name that `projects.json` gives to another project; two projects are never merged |
| Breaking programs that need private files (`acme.json`, SSH keys, database folders) | files and folders with mode `600` or `700` get no kilt entries, so their mode does not change |
| Changing a deploy folder (git hooks) | nobody can write to `.git`; `"files": "ro"` for a project |
| Changing Python under sudo | `#!/usr/bin/python3 -I`, a path that belongs to root, `env_reset` |
| A bad settings file | `/etc/kilt/config.json` and `/etc/kilt/projects.json` must belong to root, and only root may write to them; kilt checks the type of every field; system folders and `/home` cannot be project folders |
| Breaking `sshd_config` | if `sshd_config` includes `/etc/ssh/sshd_config.d/*.conf`, kilt writes only `/etc/ssh/sshd_config.d/00-kilt.conf`; otherwise its block has a start and an end marker, and text after it is kept; the block ends with `Match all`; `sshd -t` checks the result, and the old files come back if there is an error |
| Mistakes by the admin | full root needs a random code typed by hand; risky questions have "Cancel" as the default; the last root key cannot be removed; private keys, weak RSA keys and repeated keys are not accepted; root key lines that kilt does not understand are kept as they are; control characters are removed from names before they reach the screen or the log |

## How kilt was tested

[`tests/security.py`](../tests/security.py) installs kilt on a throwaway machine. It starts two test compose projects, `demo` and `other`, and adds three test accounts: one with **read** on `demo`, one with **root on project** on `demo`, and one without projects. Then it tries the attacks below. Some of these attacks worked against older versions. None of them work now.

1. **Network:** connect from the shell to the published ports of both projects on `127.0.0.1`, to container addresses in Docker networks, and to `169.254.169.254`. With **read**, a person cannot reach even their own project's services. With **root on project**, a person reaches only their own project. Nobody reaches cloud metadata. The internet stays open.
2. **Files:** with **read**, open `.env`, `.git/config` and a file in a `secrets` folder, and change a project file. Open the real project path under `/srv`, and enter another person's project through `/run/kilt/view`.
3. **New files:** a new normal file and a new secret file are closed for **read** until the next sync. After the sync, the normal file opens and the secret stays closed.
4. **Container escape:** `kilt exec` → `chown 0:0` and `chmod 4755` on a program in a shared folder → run it on the server; make a device file in a shared folder and read it on the server.
5. **Race with file rights:** for 20 seconds, swap a folder and a link to a root folder with `renameat2(RENAME_EXCHANGE)`, while root runs `kilt sync` again and again.
6. **Project names:** `projects.json` gives the name `other` to the compose project `demo`. The compose project `other` must not take this name, and the two projects must not be merged. The compose projects `shop_v2` and `shop-v2` must get two different names, the same in any `docker ps` order.
7. **Removing access:** start a process that keeps making new copies of itself, then remove the person with the same function that the menu uses. No process may stay, the person may not log in, and the user ID may not be given out again.
8. **Setgid files:** with **root on project**, copy `bash` to the home folder, give it the project's group and the setgid bit. Then change the level to **read**, and then take the project away. The file must lose the bit and give no access.
9. **User namespaces:** no personal account may have a line in `/etc/subuid` or `/etc/subgid`, and the lines of other users stay.
10. **Private files:** a `600` file stays `600` after the sync and is closed for **read**; `acme.json` is closed for **read**; kilt does not walk `node_modules` and folders from `exclude`, and **read** and **root on project** cannot open the files there, even files that everyone can read.
11. **Ports, cron and at:** open a port on the server, use `ssh -R`, add a crontab; personal accounts are in `/etc/at.deny`.
12. **Bad command input:** `--privileged`, `; id`, `$(id)`, other project names, `../../etc`, unknown commands, `exec` and `restart` with **read**.
13. **Keys:** add a key to `~/.ssh/authorized_keys`.
14. **Limits:** 256 processes and 1 GB of memory for each account.
15. **Settings:** `/`, `/home`, `/usr/local` and `/var` as project folders, a `config.json` that everyone can write to, and a `projects.json` with a wrong field type.
16. **Firewall at start:** delete the kilt table, then run `kilt boot` with a broken `config.json`, and again without docker. Both times the block-only rules must be loaded. Then `systemctl restart nftables` and `systemctl reload nftables` with a config that removes the kilt table: the rules must come back.
17. **Removing kilt:** `kilt uninstall --remove-users --yes --purge`. Afterwards there must be no nft table, no kilt units, sudo rule or sshd settings, no users with IDs 70000–79999, no groups `kilt` or `p-*`, and no kilt entries in the ACLs of `/srv` and `/srv/demo`. The project files must stay.

The tests run in CI on every push, with the menu in English and in Russian. Run them only on a machine you can throw away: they install kilt, change `sshd_config`, add users and firewall rules. On your computer: `./tests/run.sh` (you only need Docker).
