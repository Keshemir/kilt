# Why kilt is built this way

Some parts of kilt look more complex than they need to be. This page explains them. In most cases the simple way has a security hole, and the complex way closes it.

kilt runs as root and works on folders that other people can write to. So the main rule is: never trust a path, a file or an input that a person can change.

## Files and permissions

**ACLs are written by kilt itself, not with `setfacl`.**
`setfacl -R` checks a file by its name and then changes it by the same name. Between these two steps, a person with write access can replace a folder with a link to `/root` or `/etc`, and root gives them access there. kilt opens every file once with `O_PATH | O_NOFOLLOW` and changes the ACL on the open file (`acl_apply`, `acl_tree`). Python has no ACL library, so kilt writes the `system.posix_acl_*` attributes directly. The format is a stable part of the Linux kernel. It is also much faster than starting `setfacl` once per file in a big project.

**Paths are opened one part at a time** (`open_nofollow`).
Python has no `openat2(RESOLVE_NO_SYMLINKS)`. Opening each part with `O_NOFOLLOW` gives the same result: no link on the way is followed.

**kilt compares before it writes.**
`acl_apply` reads the current ACL and writes only when it is different. Otherwise every sync would change the ctime of every file, and backup tools would copy everything again.

**The walk stops at other filesystems, other projects and hard links owned by root.**
Without these checks, the walk could leave the project through a mount, give one project's people access to a nested project, or reach `/etc/shadow` through a hard link. `kilt setup` also turns on `fs.protected_hardlinks`.

**Files that only their owner can read stay as they are.**
Programs like OpenSSH, Traefik (`acme.json`) and libpq (`.pgpass`) refuse files with group access. An ACL entry would make a 0600 file look like 0640, and these programs would stop working.

**Excluded folders and `node_modules` get an explicit deny.**
If kilt only removed its entries there, the normal "other" bits would apply, and people could read world-readable files inside. One deny entry on the folder closes it without walking millions of files.

**The policy is one small function, `rights()`.**
It decides what "read" and "root on project" may do with a file. It has no side effects, so `tests/unit.py` tests it without root.

## Project folders

**People use a second mount of the project, not the real path.**
A person with "root on project" is root inside the project's containers. Through a shared folder they could create a setuid program or a device file and then use it on the server. The second mount under `/run/kilt/view` has `nosuid,nodev`, so these files do nothing there. The real path is closed with a `kilt:---` ACL entry.

**After mounting, kilt checks that the mount is the same folder.**
`mount` takes a path and opens it again. Someone could swap the folder in between. kilt opens the folder first, mounts, and then compares the inode of the mount with the open folder. If they differ, it unmounts.

**The entrance folder belongs to the project group, mode 750.**
Without it, a person without the project could walk into `/run/kilt/view/<project>/m` and read files that everyone can read.

**Project names depend only on the compose name.**
If the name depended on the order of containers, recreating containers could move a name, and the access that belongs to it, to another project.

## People and accounts

**User IDs come from their own range and are never reused.**
A new person must never get the files, cron jobs or ACL entries of a deleted person. The range also lets one nftables rule cover every personal account.

**Removing a person stops all their processes with one `kill(-1)`.**
kilt forks, switches to that user and calls `kill(-1)`. The kernel then stops every process of that user at once. `pkill` goes through a list and misses processes that start new copies of themselves. The check `is_kilt_uid` makes sure this never runs for root or a normal system user.

**setuid and setgid copies are removed when access goes down.**
A person could copy `bash`, give it the project group and the setgid bit, and keep using the project after removal. kilt removes these bits from the person's files in their home and temporary folders. It works on open files, never by path.

**kilt deletes the subuid and subgid ranges of personal accounts.**
With these ranges, a person can drop their groups in a user namespace. Then the `kilt:---` entry that closes the project folders no longer matches them.

**Keys live in `/etc/kilt/keys` and belong to root.**
If a key were in `~/.ssh/authorized_keys`, the person could add a second key and keep access after removal. The key file has mode 0640 and the person's group, because sshd reads it as that user.

**Files written into a person's home use `O_EXCL | O_NOFOLLOW`.**
The home belongs to the person. root must not follow a link that the person placed there.

## Container commands

**People run `kilt ps`, `kilt logs` and so on through sudo, and kilt checks everything itself.**
The `docker` group is the same as root, so people never get it. Before calling docker, kilt clears the environment, changes to `/`, takes the caller from `SUDO_UID`, allows only listed log flags, puts `--` before service names and checks every name against the project (`caller`, `isolate`, `pick_project`, `log_flags`). `up`, `pull`, `run` and `cp` are not allowed, because they could mount the host or copy files as root.

**Fixed paths for `sudo` and `kilt`.**
The person controls `PATH`. Running `sudo` from `PATH` could run their own program.

**Python runs with `-I`.**
root code must not load modules from `PYTHONPATH` or the current folder.

**The lock ignores Ctrl-Z while a person's command holds it.**
Otherwise a person could stop `kilt restart` in the middle and keep the lock, and the admin could not remove anyone. The lock also has a deadline.

## Network

**One table, replaced at once.**
kilt loads `table inet kilt` as one transaction: create, delete, create again. There is no moment without rules.

**A deny-only ruleset comes first.**
At boot, or when the settings cannot be read, kilt loads a ruleset that only blocks. It does not need docker or the config. Exceptions for "root on project" come with the next sync. If kilt waited for docker at boot, sshd could wait too.

**`permitopen` lists both `127.0.0.1` and `localhost`.**
sshd compares these values as plain text. A person may type either.

## Settings and system files

**Settings files must belong to root.**
`config.json` and `projects.json` decide what root does. They are opened with `O_NOFOLLOW`, and kilt refuses them if someone else can write to them.

**System files are written safely** (`write_root_file`).
kilt writes to a temporary file with the right owner and mode, syncs it to disk, and then renames it. There is never a half-written or world-readable file.

**`sudoers` is checked with `visudo`, and `sshd_config` with `sshd -t`.**
A broken file in either place locks everyone out. kilt checks the new file and keeps the old one if the check fails. The temporary file for sudoers has a dot in its name, because sudo skips such files.

**The sshd settings go to `sshd_config.d/00-kilt.conf`.**
sshd uses the first value it finds. A file that comes first wins over later `Match` blocks. The file ends with `Match all`, so it does not change the lines that follow it in the main config.

## Menu

**Everything printed goes through `clean()`.**
Container names and key comments come from other people. Without cleaning, they could send terminal control codes to the admin's screen.

**Full root needs a random code.**
A stray Enter must not give someone full root.

**Other accounts are read carefully** (`others()`).
Their files are opened with `O_NONBLOCK | O_NOFOLLOW`, checked to be regular files, and read with a size limit. A FIFO or a huge file in someone else's `~/.ssh` must not hang the menu.

**Closing root sessions checks the process start time** (`kick_fp`).
Process IDs are reused. kilt kills an sshd process only if it started before the log line, and it never touches the admin's own session.
