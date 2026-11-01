import subprocess
from pathlib import Path

SCRIPT = str(Path(__file__).resolve().parent.parent / "install.sh")


def run(*args):
    return subprocess.run(["bash", SCRIPT, *args], capture_output=True, text=True)


def test_join_validates_arguments():
    assert run("--join").returncode == 2
    r = run("--join", "not-an-ip", "--dry-run")
    assert r.returncode == 2 and "IPv4" in r.stderr
    assert run("--join", "10.0.0.1", "--peer-user", "bad user", "--dry-run").returncode == 2
    assert run("--join", "10.0.0.1", "--priority", "x", "--dry-run").returncode == 2


def test_join_dry_run_changes_nothing_and_update_is_init():
    r = run("--join", "192.0.2.10", "--dry-run")
    assert r.returncode == 0 and "Joining the twin at 192.0.2.10" in r.stdout and "[dry-run]" in r.stdout
    assert "twin of 192.0.2.10" in r.stdout
    u = run("--update", "--dry-run")
    assert u.returncode == 0 and "Installing Debian packages" in u.stdout


def test_help_lists_modes():
    r = run("--help")
    assert "--join" in r.stdout and "--update" in r.stdout and "--fail2ban" in r.stdout


def _copy_tree(tmp_path):
    import os, shutil
    dst = tmp_path / "debrev"
    shutil.copytree(os.path.dirname(SCRIPT), dst, ignore=shutil.ignore_patterns(".git", "tests", "__pycache__"))
    return dst


def test_refuses_to_install_where_keepalived_would_disable_its_scripts(tmp_path):
    """keepalived ignores scripts that others can write; a server that never fails over must not be installed."""
    import os, pytest
    if os.geteuid() != 0:
        pytest.skip("needs root")
    dst = _copy_tree(tmp_path)
    (dst / "bin" / "debrev-health").chmod(0o777)
    r = subprocess.run(["bash", str(dst / "install.sh"), "--init"], capture_output=True, text=True)
    assert r.returncode == 1
    assert "never fail over" in r.stderr and "debrev-health" in r.stderr
    assert "Installing Debian packages" not in r.stdout     # stopped before touching the system


def test_refuses_a_directory_owned_by_somebody_else(tmp_path):
    import os, pytest
    if os.geteuid() != 0:
        pytest.skip("needs root")
    dst = _copy_tree(tmp_path)
    os.chown(dst, 1000, 1000)
    r = subprocess.run(["bash", str(dst / "install.sh"), "--init"], capture_output=True, text=True)
    assert r.returncode == 1 and str(dst) in r.stderr
