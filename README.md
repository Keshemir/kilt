# kilt

Give people SSH access to one docker compose project, not to the whole server.

*Kilt* (кілт) means *key* in Kazakh. [Русская версия](docs/README.ru.md)

## Why

You have one server. It runs a shop, a blog and an API, each in its own docker compose project. A new developer needs to read the shop logs. A contractor needs to restart the API for a week.

Usually there are two bad options. You give them root, and they can see everything. Or you set up users, groups, ACLs, sudo rules and firewall rules by hand, and you forget one of them.

kilt does this work for you. You open a menu on the server, pick a person, pick a project and pick a level. That's it.

```
Access to server 203.0.113.10
> ➕ Add a person
  alice                   whole server, root   SHA256:Xp3kQ9vT2mLa…
  bob                     shop (root on project), blog (read)
  carol                   no projects
  ── not managed by this menu ──
  · deploy: separate account, docker group — same as root, keys: 1
  Exit
```

kilt is one Python file with no dependencies. The menu is drawn by [gum](https://github.com/charmbracelet/gum) and works in English or Russian.

## Quick start

You need Debian or Ubuntu with systemd, Python 3.9 or newer and docker compose v2.

```bash
apt install -y sudo gum nftables
install -m 755 kilt.py /usr/local/bin/kilt
kilt setup
kilt
```

`gum` is in Debian 13 and newer. On older systems, install it [from the gum page](https://github.com/charmbracelet/gum#installation).

kilt runs as root and changes the sshd settings, users and firewall rules. Please read the code before you install it, and try it on a test server first. `kilt --version` shows the version, and `kilt uninstall` removes kilt again (see [Removing kilt](#removing-kilt)).

## What a person sees

Bob has **read** on the blog and **root on project** on the shop. He logs in with his own key:

```
$ ssh bob@server
bob@server:~$ ls
blog  shop
bob@server:~$ cd shop
bob@server:~/shop$ kilt ps                 # containers of the shop
bob@server:~/shop$ kilt logs -f web        # follow the logs
bob@server:~/shop$ kilt restart web        # needs "root on project"
bob@server:~/shop$ kilt exec web sh        # needs "root on project"
```

He cannot see other projects, cannot use `docker` or `sudo`, and cannot reach the databases of other projects.

## Levels of access

Root logs in as `root@server` and can do everything. Everyone else logs in with their own login. A person without projects can only look around: processes, disk, load. A person with projects gets **read** or **root on project** for each project.

|  | no projects | read | root on project |
|---|---|---|---|
| Read project files | — | ✓ | ✓ |
| Read secrets (`.env`, keys, tokens, `.git/config`, `secrets/`) | — | — | ✓ |
| Change project files | — | — | ✓ (can be turned off) |
| `kilt ps`, `kilt logs` | — | ✓ | ✓ |
| `kilt restart`, `stop`, `start`, `exec` | — | — | ✓ |
| Connect to the project's database, Redis, web ports | — | — | ✓ |
| Connect to other projects, private networks, cloud metadata | — | — | — |
| Use the internet (git, curl) | ✓ | ✓ | ✓ |
| Open ports, cron, `at`, `docker`, `sudo` | — | — | — |

Each person can use up to 256 processes, 1 GB of memory and one CPU, and can write files up to 4 GB.

## The menu

Run `kilt` as root. To add a person, choose the kind of access, type a login, pick projects and paste their public key (`ssh-ed25519 AAAA…`). Press Enter on a person to change their level, add or remove a project, change the key or delete them. When you change or remove access, all their processes stop at once.

The menu tries to stop mistakes. To give full root, you must type a random code from the screen. Risky questions have "Cancel" as the default. You cannot remove the last root key. Private keys, weak RSA keys and keys that are already used are refused.

## Settings

`kilt setup` creates `/etc/kilt/config.json` ([example](examples/config.json)):

```json
{
  "host": "203.0.113.10",
  "closed": ["/opt", "/srv"],
  "service_keys": [],
  "language": "en"
}
```

- `host` is the address that kilt shows in "They log in like this: ssh …". If it is empty, kilt uses the first address from `hostname -I`.
- `closed` lists the folders with your projects. People cannot open these folders directly. They get to a project only through `~/<project>`, a link to the same folder mounted again with `nosuid,nodev`. Changes there are real. System folders, `/home` and `/var` are not allowed here.
- `service_keys` lists comments of root keys that the menu should not show or touch, for example a CI key.
- `language` is `en` or `ru`. If it is empty, kilt uses the system language.

kilt finds projects by their docker compose labels. A project keeps its compose name if that name is short and simple (small letters, numbers and `-`, up to 24 characters). Otherwise kilt cleans the name and adds 5 characters from its hash, for example `shop_v2` becomes `shop-v2-1a2b3`. The name depends only on the compose name, so it does not change when containers are created again. If you want to rename a project, point it to another folder or hide some files, add `/etc/kilt/projects.json` ([example](examples/projects.json)):

```json
{
  "shop": {"compose": "shop-prod", "dir": "/srv/shop", "hide": ["notes-with-passwords.md"]},
  "site": {"compose": "site", "dir": "/opt/site", "files": "ro"}
}
```

The key (`shop`) is the name people see in the menu and in `~/shop`. `hide` closes more files for **read**. `exclude` lists folders that kilt does not walk at all, for example `"exclude": ["data", "uploads/cache"]` for big data folders: kilt gives them no rights, so people get only the normal Linux permissions there. This is not a way to hide files, use `hide` for that. `"files": "ro"` means that **root on project** cannot change files, which is useful for folders that CI deploys from. The project folder must be inside one of the `closed` folders.

Both files must belong to root, and only root may write to them. If a file is wrong, kilt stops with an error instead of guessing.

## How it works

kilt uses normal Linux tools and does not run a daemon.

Root keys stay in `/root/.ssh/authorized_keys` with a `#NAME` line above each one. Before every change kilt saves a copy in `/root/.ssh/kilt-backups/`. Lines it does not understand stay as they are.

Every other person is a Linux user in the group `kilt`, with a user ID between 70000 and 79999. IDs are never reused, so a new person never gets the files of an old one. Their keys are in `/etc/kilt/keys/` and belong to root, so they cannot add a second key.

Each project has two groups, `p-<project>` for read and `p-<project>-rw` for root on project. kilt sets file permissions with POSIX ACLs. It opens every file once and changes the open file, so nobody can swap a folder for a link while kilt works. New files stay closed for **read** until the next sync. Secrets stay closed for **read** all the time.

Files and folders that only their owner may open (mode `600` or `700`, for example `acme.json`, SSH keys or a database folder) get no kilt rights at all, so programs that check these modes keep working. Nobody with a personal account can open them, also not with **root on project**. kilt does not walk `node_modules`, `.venv`, `venv`, `vendor` and `site-packages`: the folder itself gets rights, the files inside keep their normal Linux permissions.

People never use the real project path. They work in `/run/kilt/view/<project>/m`, a second mount of the folder with `nosuid,nodev`. A setuid program or a device file made inside a container does nothing there.

`kilt ps`, `kilt logs` and the other container commands run through a sudo rule. kilt checks the person's groups and runs `docker` only for their project. `docker compose up`, `pull`, `run` and `cp` are not allowed.

The network is limited with nftables rules for user IDs 70000–79999. People cannot reach the server itself, private networks or cloud metadata. They can reach the DNS servers from `/etc/resolv.conf`, the internet, and the services of projects where they have root on project.

If kilt cannot build the full rules (for example, docker does not answer), it loads a basic set that only blocks: the server itself, private networks, cloud metadata, `64:ff9b::/96`. People keep DNS and the internet. The full rules also block the IPv6 networks of docker.

systemd limits memory, processes and CPU and blocks listening ports. cron and `at` are turned off for these users. kilt removes their lines from `/etc/subuid` and `/etc/subgid`, so they cannot use user namespaces to drop the `kilt` group. SSH allows only `-L` forwarding: no `-R`, no agent, no X11, no passwords, no certificates and no `AuthorizedKeysCommand`. If `sshd_config` includes `/etc/ssh/sshd_config.d/*.conf` (Debian and Ubuntu do), kilt writes its settings to `/etc/ssh/sshd_config.d/00-kilt.conf`. Otherwise it adds a marked block at the end of `sshd_config`. Either way `sshd -t` checks the result first.

When someone loses a project or goes from **root on project** to **read**, kilt stops their processes and removes setuid and setgid bits from their own files in their home folder, `/tmp`, `/var/tmp` and `/dev/shm`. Otherwise a copy of `bash` with the project's group could keep the old access.

A timer runs `kilt sync` every 10 minutes to update permissions, keys and network rules. The `kilt-boot` service sets the basic network rules and mounts the project folders when the server starts, before sshd. It does not need docker or the settings files. It also runs again when `nftables.service` restarts or reloads, because a typical `/etc/nftables.conf` starts with `flush ruleset`. Full rules come with the next sync, about 2 minutes after the start. Everything kilt does is written to `/var/log/kilt.log`, which only root can read. `kilt setup` adds `/etc/logrotate.d/kilt`, so the log is rotated every week.

All commands that kilt runs have a time limit. If someone else is changing access at the same time, kilt waits up to a minute and then says that it is busy.

## Things to know

- **Root on project means trust.** The person is root inside the project's containers. A skilled person can use that to get root on the server, more easily if a container mounts `docker.sock`, runs privileged, or shares a folder without `nosuid` or `nodev`. kilt writes a warning to its log when it sees this.
- Secrets are found by name. A password inside `config.yml` is visible with **read**, so add such files to `hide`.
- New files can be read only after the next sync, up to 10 minutes later. This is on purpose.
- If someone recreates containers without kilt, a container address can move to another project until the next sync.
- Disk space is not limited.
- The ban on listening ports needs systemd built with BPF. Debian has it. If your systemd does not, people can open ports above 1024, and `kilt setup` tells you so.
- Users created without kilt are shown in the menu but not changed. Users in `sudo`, `docker`, `wheel`, `admin`, `lxd`, `libvirt` or `disk` are marked "same as root".
- Removing someone's root key does not prove they are gone. They may have left another way in.
- If `AllowUsers` or `AllowGroups` in sshd blocks the group `kilt`, nobody with a personal account can log in. `kilt setup` warns about it but does not change your sshd settings.
- Processes that a person starts inside a container with `kilt exec` keep running after you remove the person. Restart the container if you need to be sure.
- People can see the processes of other users in `/proc`, with their command lines. Do not put passwords in command lines.
- There is no command line interface for scripts and automation yet: people and their access can be changed only in the menu. It is planned.

More details are in [SECURITY.md](.github/SECURITY.md).

## Removing kilt

```bash
kilt uninstall                  # refuses while there are personal accounts
kilt uninstall --remove-users   # deletes the personal accounts first
```

It asks you to type `yes` (or use `--yes`). Then it removes the kilt services, the firewall table, the project folder mounts under `/run/kilt`, the kilt entries in the file permissions of your project folders, the groups `kilt` and `p-*`, the sudo rule, the limits, the sysctl and logrotate files and the sshd settings. At the end it prints what it removed. Root keys in `/root/.ssh/authorized_keys` stay as they are. `/etc/kilt` and `/var/log/kilt.log` stay too, unless you add `--purge`. The file `/usr/local/bin/kilt` you remove yourself.

## Tests

`tests/security.py` installs kilt, creates two test projects and three people, and then tries to break in: through the network, files, containers, file permissions, setgid files, user namespaces, ports, keys and bad commands. It also checks the start without docker, a restart of nftables, and at the end it removes kilt with `kilt uninstall`. GitHub Actions runs it on every push, with the menu in English and in Russian.

It changes a lot on the machine, so run it only somewhere you can throw away. With Docker on your computer:

```bash
./tests/run.sh        # menu in English
./tests/run.sh ru     # menu in Russian
```

`tests/translations.py` checks that every menu text has an English version.

## Contributing

Bug reports, ideas and pull requests are welcome. Start with [CONTRIBUTING.md](.github/CONTRIBUTING.md). Please report security problems privately, as described in [SECURITY.md](.github/SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
