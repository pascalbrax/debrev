from debrev import sysinfo


def test_meminfo_and_cpu(tmp_path):
    m = sysinfo.meminfo("MemTotal: 1000 kB\nMemAvailable: 250 kB\nSwapTotal: 100 kB\nSwapFree: 40 kB\n")
    assert m["percent"] == 75.0 and m["swap_used"] == 60 * 1024
    f = tmp_path / "stat"
    f.write_text("cpu 100 0 100 800 0 0 0 0\n")
    assert sysinfo._cpu_times(str(f)) == (1000, 800)
    assert 0 <= sysinfo.cpu_percent(0.01) <= 100
    s = sysinfo.snapshot(0.01)
    assert s["cores"] >= 1 and s["mem"]["total"] > 0 and s["disks"]
    assert sysinfo.human_uptime(90061) == "1d 1h 1m"
