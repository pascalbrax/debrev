import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from debrev import state as st  # noqa: E402
from debrev.paths import Paths  # noqa: E402


@pytest.fixture(autouse=True)
def _no_real_reboot_check(monkeypatch):
    """The Security page asks whether this machine needs a restart; tests must not depend on the host's /boot."""
    from debrev import security, updates
    monkeypatch.setattr(security, "_reboot_reason", lambda: "")
    monkeypatch.setattr(updates, "waiting", lambda *a, **k: [])                         # never ask the host's apt


@pytest.fixture
def paths(tmp_path):
    p = Paths(etc=tmp_path / "etc", lib=tmp_path / "lib", cache=tmp_path / "cache",
              letsencrypt=tmp_path / "le", reload_cmd=("true",), health_check=False,
              access_log=tmp_path / "log" / "debrev.log",
              fail2ban_log=tmp_path / "log" / "fail2ban.log", fail2ban_jail=tmp_path / "etc-f2b" / "debrev.local")
    (tmp_path / "log").mkdir()
    st.init(p)
    return p


def write_host(p, name, text):
    (p.state / "hosts" / f"{name}.yaml").write_text(text)


have_nginx = shutil.which("nginx") is not None
