"""File-sharing client (library + command line)."""
import argparse
import getpass
import hashlib
import hmac
import os
import socket
import time

from common import SERVICE_PORT, CHUNK, send_msg, recv_msg, recv_exact


class FileClient:
    def __init__(self, host, port=SERVICE_PORT, timeout=60):
        self.sock = socket.create_connection((host, port), timeout=timeout)

    def login(self, user, password):
        send_msg(self.sock, {"cmd": "LOGIN", "user": user})
        r = recv_msg(self.sock)
        salt, nonce = bytes.fromhex(r["salt"]), bytes.fromhex(r["nonce"])
        key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
        send_msg(self.sock, {"proof": hmac.new(key, nonce, "sha256").hexdigest()})
        r = recv_msg(self.sock)
        if not r["ok"]:
            raise PermissionError(r["error"])
        return r["role"]

    def upload(self, path, remote_name=None):
        name = remote_name or os.path.basename(path)
        size = os.path.getsize(path)
        h = hashlib.sha256()
        with open(path, "rb") as f:                    # pre-compute checksum
            for c in iter(lambda: f.read(CHUNK), b""):
                h.update(c)
        send_msg(self.sock, {"cmd": "UPLOAD", "name": name, "size": size,
                             "sha256": h.hexdigest()})
        r = recv_msg(self.sock)
        if not r["ok"]:
            raise RuntimeError(r["error"])
        t0 = time.time()
        with open(path, "rb") as f:
            while True:
                c = f.read(CHUNK)
                if not c:
                    break
                self.sock.sendall(c)
        r = recv_msg(self.sock)
        if not r["ok"]:
            raise RuntimeError(r["error"])
        return size, time.time() - t0

    def download(self, name, dest_dir="."):
        send_msg(self.sock, {"cmd": "DOWNLOAD", "name": name})
        r = recv_msg(self.sock)
        if not r["ok"]:
            raise RuntimeError(r["error"])
        size, want = r["size"], r["sha256"]
        out = os.path.join(dest_dir, name)
        h, got, t0 = hashlib.sha256(), 0, time.time()
        with open(out, "wb") as f:
            while got < size:
                c = self.sock.recv(min(CHUNK, size - got))
                if not c:
                    raise ConnectionError("server closed during download")
                f.write(c)
                h.update(c)
                got += len(c)
        secs = time.time() - t0
        if h.hexdigest() != want:
            raise RuntimeError("checksum mismatch - file corrupted")
        return out, size, secs

    def list(self):
        send_msg(self.sock, {"cmd": "LIST"})
        return recv_msg(self.sock)["files"]

    def delete(self, name):
        send_msg(self.sock, {"cmd": "DELETE", "name": name})
        r = recv_msg(self.sock)
        if not r["ok"]:
            raise RuntimeError(r["error"])

    def close(self):
        try:
            send_msg(self.sock, {"cmd": "QUIT"})
        except OSError:
            pass
        self.sock.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=SERVICE_PORT)
    ap.add_argument("-u", "--user", required=True)
    ap.add_argument("-p", "--password")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    sub.add_parser("upload").add_argument("path")
    d = sub.add_parser("download")
    d.add_argument("name")
    d.add_argument("-o", "--outdir", default=".")
    sub.add_parser("delete").add_argument("name")
    a = ap.parse_args()

    pw = a.password or getpass.getpass("password: ")
    c = FileClient(a.host, a.port)
    try:
        role = c.login(a.user, pw)
        if a.cmd == "list":
            print(f"{'NAME':25}{'OWNER':8}{'SIZE':>12}  {'UPLOADED':20}DL")
            for f in c.list():
                print(f"{f['name']:25}{f['owner']:8}{f['size']:>12}  "
                      f"{f['uploaded']:20}{f['downloads']}")
        elif a.cmd == "upload":
            n, s = c.upload(a.path)
            print(f"uploaded {n} bytes in {s:.2f}s ({n*8/1e6/max(s,1e-9):.1f} Mbps)")
        elif a.cmd == "download":
            out, n, s = c.download(a.name, a.outdir)
            print(f"saved {out}: {n} bytes in {s:.2f}s ({n*8/1e6/max(s,1e-9):.1f} Mbps)")
        elif a.cmd == "delete":
            c.delete(a.name)
            print("deleted")
    except (RuntimeError, PermissionError) as e:
        print("ERROR:", e)
    finally:
        c.close()


if __name__ == "__main__":
    main()
