"""Simultaneous-transfer test: N clients upload then download at the same time.

Usage: python3 test_concurrent.py --host 10.0.0.1 -n 5 --size 20
"""
import argparse
import hashlib
import os
import tempfile
import threading
import time

from client import FileClient
from common import SERVICE_PORT

CREDS = [("alice", "alice123"), ("bob", "bob123"), ("carol", "carol123")]
results, lock = [], threading.Lock()


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(65536), b""):
            h.update(c)
    return h.hexdigest()


def worker(i, host, port, size_mb, tmp, barrier):
    user, pw = CREDS[i % len(CREDS)]
    src = os.path.join(tmp, f"src_{i}.bin")
    with open(src, "wb") as f:
        f.write(os.urandom(size_mb * 1024 * 1024))
    name = f"test_{i}.bin"
    c = FileClient(host, port)
    c.login(user, pw)
    barrier.wait()                                   # all start together
    n, up_s = c.upload(src, name)
    dl_dir = os.path.join(tmp, f"dl_{i}")
    os.makedirs(dl_dir)
    out, _, dn_s = c.download(name, dl_dir)
    ok = sha(src) == sha(out)
    c.close()
    with lock:
        results.append((i, user, n, up_s, dn_s, ok))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=SERVICE_PORT)
    ap.add_argument("-n", type=int, default=5, help="number of clients")
    ap.add_argument("--size", type=int, default=20, help="MB per file")
    a = ap.parse_args()
    barrier = threading.Barrier(a.n)
    with tempfile.TemporaryDirectory() as tmp:
        t0 = time.time()
        ts = [threading.Thread(target=worker,
              args=(i, a.host, a.port, a.size, tmp, barrier)) for i in range(a.n)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        total = time.time() - t0
    print(f"\n{'client':7}{'user':8}{'MB':>5}{'up Mbps':>10}{'down Mbps':>11}  integrity")
    for i, u, n, us, ds, ok in sorted(results):
        print(f"{i:<7}{u:8}{n/1e6:>5.0f}{n*8/1e6/us:>10.1f}{n*8/1e6/ds:>11.1f}  "
              f"{'OK' if ok else 'CORRUPT'}")
    print(f"\n{len(results)}/{a.n} clients finished, all intact: "
          f"{all(r[5] for r in results)}")


if __name__ == "__main__":
    main()
