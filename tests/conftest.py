import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from debrev import state as st  # noqa: E402
from debrev.paths import Paths  # noqa: E402


@pytest.fixture
def paths(tmp_path):
    p = Paths(etc=tmp_path / "etc", lib=tmp_path / "lib", cache=tmp_path / "cache",
              letsencrypt=tmp_path / "le", reload_cmd=("true",), health_check=False,
              access_log=tmp_path / "log" / "debrev.log")
    (tmp_path / "log").mkdir()
    st.init(p)
    return p


def write_host(p, name, text):
    (p.state / "hosts" / f"{name}.yaml").write_text(text)


have_nginx = shutil.which("nginx") is not None
