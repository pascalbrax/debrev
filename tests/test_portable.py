import subprocess
import sys

import pytest
import yaml

from conftest import write_host
from debrev import portable, state as st
from debrev.paths import APP_DIR, Paths

HOSTS = {
    "a.example.com": "domain: a.example.com\nupstream: http://10.0.0.1:3000\nwebsockets: true\n",
    "b.example.com": "domain: b.example.com\nupstream: http://10.0.0.2:80\naccess_list: office\nnote: |\n  line one\n  line two\n",
}


@pytest.fixture
def source(paths):
    for d, t in HOSTS.items():
        write_host(paths, d, t)
    (paths.state / "access_lists" / "office.yaml").write_text("allow:\n  - 192.168.1.0/24\n")
    s = yaml.safe_load((paths.state / "settings.yaml").read_text())
    s["acme"] = {"email": "ops@example.com", "server": "staging", "auto": True}
    s["security"] = {"rate": 50}
    (paths.state / "settings.yaml").write_text(st.dump_yaml(s))
    st.commit(paths, "seed", "t")
    return paths


def fresh(tmp_path):
    p = Paths(etc=tmp_path / "e2", lib=tmp_path / "l2", cache=tmp_path / "c2", letsencrypt=tmp_path / "le2",
              reload_cmd=("true",), health_check=False)
    st.init(p)
    return p


def test_export_has_everything_and_no_secrets(source):
    (source.certs_dir / "a.example.com").mkdir(parents=True)
    (source.certs_dir / "a.example.com" / "privkey.pem").write_text("-----BEGIN PRIVATE KEY-----\nSECRETKEY\n")
    text = portable.export_text(source)
    doc = yaml.safe_load(text)
    assert doc["debrev_export"] == 1
    assert [h["domain"] for h in doc["hosts"]] == ["a.example.com", "b.example.com"]
    assert doc["access_lists"]["office"]["allow"] == ["192.168.1.0/24"]
    assert doc["settings"]["acme"]["email"] == "ops@example.com" and doc["settings"]["security"]["rate"] == 50
    assert "SECRETKEY" not in text and "PRIVATE KEY" not in text and "format" not in doc["settings"]


def test_round_trip_into_a_fresh_server(source, tmp_path):
    text = portable.export_text(source)
    dst = fresh(tmp_path)
    doc, errs = portable.parse(text)
    assert not errs
    pl = portable.plan(dst, doc, settings=True)
    assert pl["problems"] == 0
    ok, msg = portable.apply(dst, pl, "tester")
    assert ok, msg
    hosts, acls, errors, _ = st.load(dst)
    assert not errors and sorted(h["domain"] for h in hosts) == ["a.example.com", "b.example.com"]
    assert hosts[1]["access_list"] == "office"
    assert (dst.state / "hosts" / "b.example.com.yaml").read_text() == (source.state / "hosts" / "b.example.com.yaml").read_text()
    s, _ = st.load_settings(dst)
    assert s["acme"]["email"] == "ops@example.com" and s["security"]["rate"] == 50
    assert not st.is_dirty(dst) and "import from file: 2 host(s), 1 access list(s), settings" in st.log(dst, 1)[0]["message"]
    # and the exported text of the copy is the same configuration
    a, b = yaml.safe_load(text), yaml.safe_load(portable.export_text(dst))
    assert (a["hosts"], a["access_lists"], a["settings"]) == (b["hosts"], b["access_lists"], b["settings"])


def test_settings_only_with_the_flag(source, tmp_path):
    dst = fresh(tmp_path)
    doc, _ = portable.parse(portable.export_text(source))
    pl = portable.plan(dst, doc)
    assert any(i["kind"] == "settings" and i["action"] == "skip" for i in pl["items"])
    assert portable.apply(dst, pl, "t")[0]
    assert st.load_settings(dst)[0]["acme"]["email"] is None


def test_existing_hosts_are_skipped_unless_overwrite(source, tmp_path):
    dst = fresh(tmp_path)
    write_host(dst, "a.example.com", "domain: a.example.com\nupstream: http://10.9.9.9:1\n")
    st.commit(dst, "mine", "t")
    doc, _ = portable.parse(portable.export_text(source))
    pl = portable.plan(dst, doc)
    assert {(i["name"], i["action"]) for i in pl["items"] if i["kind"] == "host"} == {("a.example.com", "skip"), ("b.example.com", "new")}
    assert portable.apply(dst, pl, "t")[0]
    assert "10.9.9.9" in (dst.state / "hosts" / "a.example.com.yaml").read_text()
    pl = portable.plan(dst, doc, overwrite=True)
    assert portable.apply(dst, pl, "t")[0]
    assert "10.0.0.1" in (dst.state / "hosts" / "a.example.com.yaml").read_text()


def test_invalid_entry_blocks_everything(source, tmp_path):
    dst = fresh(tmp_path)
    doc, _ = portable.parse(portable.export_text(source))
    doc["hosts"].append({"domain": "bad.example.com", "upstream": "not a url"})
    pl = portable.plan(dst, doc)
    assert pl["problems"] == 1
    ok, msg = portable.apply(dst, pl, "t")
    assert not ok and not list((dst.state / "hosts").glob("*.yaml"))


def test_unknown_keys_and_newer_formats_are_rejected(source):
    text = portable.export_text(source)
    assert portable.parse(text.replace("debrev_export: 1", "debrev_export: 99"))[0] is None
    assert portable.parse(text + "surprise: 1\n")[0] is None
    assert portable.parse("- just\n- a list\n")[0] is None
    assert portable.parse("nothing: here\n")[0] is None
    assert portable.parse("a: [unclosed")[0] is None
    assert portable.parse("x" * (portable.MAX_BYTES + 1))[0] is None


def test_older_plain_host_list_still_imports(paths):
    doc, errs = portable.parse("hosts:\n  - {domain: old.example.com, upstream: 'http://10.0.0.5:80', extra_npm_field: 1}\n")
    assert not errs
    pl = portable.plan(paths, doc)
    assert pl["problems"] == 0 and portable.apply(paths, pl, "t")[0]
    assert (paths.state / "hosts" / "old.example.com.yaml").exists()


def test_failed_validation_undoes_the_import(source, tmp_path):
    """A host naming an access list that exists nowhere, or settings that do not validate, must leave no trace."""
    dst = fresh(tmp_path)
    doc, _ = portable.parse(portable.export_text(source))
    doc["access_lists"] = {}                                  # b.example.com refers to 'office'
    pl = portable.plan(dst, doc)
    assert pl["problems"] == 1 and not portable.apply(dst, pl, "t")[0]
    doc, _ = portable.parse(portable.export_text(source))
    doc["settings"]["security"] = {"rate": 99999}
    pl = portable.plan(dst, doc, settings=True)
    ok, msg = portable.apply(dst, pl, "t")
    assert not ok and "rolled back" in msg
    assert not st.is_dirty(dst) and not list((dst.state / "hosts").glob("*.yaml"))
    assert st.load_settings(dst)[0]["security"]["rate"] == 30


def test_hostile_file_names_cannot_escape_the_state_folder(paths):
    doc = {"debrev_export": 1, "hosts": [{"domain": "../../evil", "upstream": "http://10.0.0.1:1"}],
           "access_lists": {"../x": {"allow": ["10.0.0.0/8"]}}}
    pl = portable.plan(paths, doc)
    assert pl["problems"] == 2 and not pl["writes"]


def test_cli_export_then_import(source, tmp_path):
    out = tmp_path / "all.yaml"
    env = {"DEBREV_ETC": "", "PATH": "/usr/bin:/bin"}
    def run(*a, root):
        return subprocess.run([sys.executable, "-m", "debrev", *a], cwd=APP_DIR, capture_output=True, text=True,
                              env={"PATH": "/usr/bin:/bin", "DEBREV_ROOT": str(root), "DEBREV_AUTHOR": "t"})
    out.write_text(portable.export_text(source))
    root = tmp_path / "root"
    (root / "var/lib/debrev").mkdir(parents=True)
    (root / "etc/debrev").mkdir(parents=True)
    assert run("init", root=root).returncode == 0
    r = run("import", str(out), root=root)                     # dry run
    assert r.returncode == 0 and "dry run" in r.stdout and "a.example.com" in r.stdout
    assert not list((root / "var/lib/debrev/state/hosts").glob("*.yaml"))
    r = run("import", str(out), "--write", root=root)
    assert r.returncode == 0, r.stdout + r.stderr
    assert (root / "var/lib/debrev/state/hosts/b.example.com.yaml").exists()
    r = run("export", root=root)
    assert r.returncode == 0 and "a.example.com" in r.stdout and "debrev_export: 1" in r.stdout
