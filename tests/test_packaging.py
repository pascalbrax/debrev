import ast
import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def third_party_imports() -> set[str]:
    mods = set()
    for f in list((ROOT / "debrev").glob("*.py")) + [ROOT / "bin" / "debrev"]:
        if not f.exists():
            continue
        try:
            tree = ast.parse(f.read_text())
        except SyntaxError:
            continue
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                mods |= {a.name.split(".")[0] for a in n.names}
            elif isinstance(n, ast.ImportFrom) and n.level == 0 and n.module:
                mods.add(n.module.split(".")[0])
    return {m for m in mods if m not in sys.stdlib_module_names and m not in ("debrev", "__future__")}


def requirements() -> set[str]:
    return {l.split("#")[0].strip() for l in (ROOT / "requirements.apt").read_text().splitlines() if l.split("#")[0].strip()}


@pytest.mark.skipif(not shutil.which("dpkg"), reason="needs dpkg")
def test_every_import_comes_from_a_package_listed_in_requirements_apt():
    reqs = requirements()
    problems = []
    for m in sorted(third_party_imports()):
        spec = importlib.util.find_spec(m)
        if spec is None or not spec.origin:
            problems.append(f"{m}: not installed here")
            continue
        r = subprocess.run(["dpkg", "-S", spec.origin], capture_output=True, text=True)
        pkg = r.stdout.split(":")[0].strip() if r.returncode == 0 else None
        if pkg is None:
            problems.append(f"{m}: not from a Debian package ({spec.origin})")
        elif pkg not in reqs:
            problems.append(f"{m}: package {pkg} is not in requirements.apt")
    assert not problems, "\n".join(problems)
