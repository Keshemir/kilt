#!/usr/bin/python3 -I
"""Checks the menu texts in kilt.py: every Russian text has an English version in EN.
English texts inside _() are fine too; they are listed as "needs a Russian translation"."""
import ast, os, re, string, sys

path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "kilt.py")
tree = ast.parse(open(path, encoding="utf-8").read())
doc = ast.get_docstring(tree, clean=False)
en_node = next(n for n in tree.body if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "EN")
problems, notes, EN = [], [], {}


def plain(n):
    return isinstance(n, ast.Constant) and isinstance(n.value, str)


for k, v in zip(en_node.value.keys, en_node.value.values):
    if not (plain(k) or isinstance(k, ast.Name)):
        problems.append(f"line {getattr(k, 'lineno', v.lineno)}: the Russian text in EN is not a plain string")
    elif not plain(v):
        problems.append(f"line {v.lineno}: the English version is not a plain string")
    else:
        EN[doc if isinstance(k, ast.Name) else k.value] = v.value
in_en = {id(n) for n in ast.walk(en_node)}
CYR = re.compile("[А-Яа-яЁё]")

calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "_"]
used = {n.args[0].value for n in calls if n.args and isinstance(n.args[0], ast.Constant)} | {doc}
wrapped = {id(n.args[0]) for n in calls if n.args}
docstrings = {id(n.body[0].value) for n in ast.walk(tree)
              if isinstance(n, (ast.Module, ast.FunctionDef, ast.ClassDef)) and n.body
              and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant)}


def fields(s):
    return sorted((f, spec or "", conv or "") for _t, f, spec, conv in string.Formatter().parse(s) if f is not None)


for n in ast.walk(tree):
    if isinstance(n, ast.Constant) and isinstance(n.value, str) and CYR.search(n.value) \
            and id(n) not in wrapped and id(n) not in docstrings and id(n) not in in_en:
        problems.append(f"line {n.lineno}: Russian text outside _(): {n.value[:60]!r}")
for k in sorted(used):
    if not CYR.search(k):
        notes.append(f"needs a Russian translation: {k[:80]!r}")
    elif k not in EN:
        problems.append(f"no English version: {k[:80]!r}")
    elif fields(k) != fields(EN[k]):
        problems.append(f"placeholders differ: {k[:60]!r} -> {EN[k][:60]!r}")
    elif CYR.search(EN[k]):
        problems.append(f"Russian letters in the English version: {EN[k][:80]!r}")
for k in sorted(set(EN) - used):
    problems.append(f"English version is not used: {k[:80]!r}")

print("\n".join(problems + notes) or f"ok: {len(used)} texts")
sys.exit(1 if problems else 0)
