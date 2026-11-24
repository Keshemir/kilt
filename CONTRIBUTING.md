# Contributing to kilt

Thank you for helping! Small fixes are welcome, and so are big ideas. If you are not sure, open an issue first and ask.

## Ways to help

- **Report a bug:** open an issue with the "Bug report" form.
- **Suggest an idea:** open an issue with the "Feature request" form.
- **Fix something:** look at issues with the label `good first issue`.
- **Improve the texts:** the menu, the README, the translations.
- **Found a security problem?** Do not open an issue. See [SECURITY.md](SECURITY.md).

## What you need

- Python 3.9 or newer. kilt uses only the standard library, so there is nothing to install.
- Docker, if you want to run the attack tests on your computer.

## Run the checks

```bash
python3 -I -m py_compile kilt.py tests/*.py   # the code compiles
python3 tests/translations.py                 # every Russian menu text has an English version
./tests/run.sh                                # attack tests, menu in English (needs Docker)
./tests/run.sh ru                             # attack tests, menu in Russian
```

The attack tests start a throwaway Linux container with systemd, install kilt there and try to break it. It takes a few minutes. GitHub Actions runs the same checks for every pull request.

**Never run `tests/security.py` on a real server.** It changes `sshd_config`, adds users and firewall rules.

## Rules for code

- **One file.** kilt is one file, `kilt.py`, and uses only the Python standard library. Please keep it like this.
- **Security first.** If your change touches users, keys, file rights, the network or containers, add or update a check in `tests/security.py`. A pull request that makes a check fail will not be merged.
- **Keep it simple.** Short functions, clear names, few comments. Write a comment only when the reason is not clear from the code. This is most important for security code.
- **No new dependencies** on the server. Use only the programs kilt already uses: `docker`, `gum`, `nft`, `sshd`, `ssh-keygen`, `sudo`, `visudo`, systemd (`systemctl`, `loginctl`), `ip`, `mount`, `crontab`, `sysctl`. Most of them are in `NEEDS` in `kilt.py`.

## Menu texts and translations

Every text that a person sees goes through `_()`. kilt can show the menu in English or Russian.

- **If you write Russian:** write the text in Russian inside `_()` and add the English version to the `EN` dictionary at the top of `kilt.py`.
- **If you do not write Russian:** write the text in English inside `_()`. That is fine: `tests/translations.py` will list it as "needs a Russian translation", and a maintainer will add it.
- **Placeholders:** use `{0}`, `{1}` and `.format(...)`, not f-strings, so the text can be translated: `_("No service {0}").format(name)`.
- **English must be simple** (level B1): short sentences, everyday words. Not "effectively root", but "same as root".

## Pull requests

1. Fork the repository and create a branch: `git checkout -b fix-short-name`.
2. Make one change per pull request. Small pull requests are reviewed faster.
3. Run the checks above.
4. Write a clear commit message: what you changed and why.
5. Open the pull request and fill in the form.

## Behaviour

Be kind and patient. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
