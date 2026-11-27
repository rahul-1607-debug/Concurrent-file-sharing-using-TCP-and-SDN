"""Concurrent TCP file-sharing server (one thread per client connection).

Features: authentication (challenge-response), role-based access,
file metadata, upload/download/list/delete, per-transfer bandwidth log.
"""
import argparse
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import socket
import threading
import time
import uuid

from common import SERVICE_PORT, CHUNK, send_msg, recv_msg, recv_exact

STORAGE = "storage"
META_FILE = "metadata.json"
USERS_FILE = "users.json"
TRANSFER_LOG = "transfers.csv"
MAX_FILE_SIZE = 1024 * 1024 * 1024        # 1 GB
NAME_RE = re.compile(r"^[A-Za-z0-9_-][A-Za-z0-9._-]{0,99}$")

# role -> allowed commands
ROLES = {
    "admin":    {"UPLOAD", "DOWNLOAD", "LIST", "DELETE"},
    "user":     {"UPLOAD", "DOWNLOAD", "LIST"},
    "readonly": {"DOWNLOAD", "LIST"},
}

meta_lock = threading.Lock()      # protects metadata dict + json file
log_lock = threading.Lock()       # protects transfers.csv
metadata = {}
users = {}
log = logging.getLogger("server")


# ---------------------------------------------------------------- users
def make_user(password, role):
    salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return {"salt": salt.hex(), "key": key.hex(), "role": role}


def load_users():
    global users
    if not os.path.exists(USERS_FILE):
        users = {
            "alice": make_user("alice123", "admin"),
            "bob":   make_user("bob123", "user"),
            "carol": make_user("carol123", "user"),
            "guest": make_user("guest123", "readonly"),
        }
        with open(USERS_FILE, "w") as f:
            json.dump(users, f, indent=2)
        log.info("created default users.json (alice/bob/carol/guest)")
    else:
        with open(USERS_FILE) as f:
            users = json.load(f)


# ------------------------------------------------------------- metadata
def load_metadata():
    global metadata
    if os.path.exists(META_FILE):
        with open(META_FILE) as f:
            metadata = json.load(f)


def save_metadata():
    """Caller must hold meta_lock. Write-then-rename = atomic on disk."""
    tmp = META_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(metadata, f, indent=2)
    os.replace(tmp, META_FILE)


def log_transfer(user, ip, op, name, nbytes, secs):
    mbps = (nbytes * 8 / 1e6) / secs if secs > 0 else 0
    log.info("%s %s by %s: %.2f MB in %.2fs = %.1f Mbps",
             op, name, user, nbytes / 1e6, secs, mbps)
    with log_lock:
        new = not os.path.exists(TRANSFER_LOG)
        with open(TRANSFER_LOG, "a") as f:
            if new:
                f.write("time,user,ip,op,file,bytes,seconds,mbps\n")
            f.write(f"{time.strftime('%H:%M:%S')},{user},{ip},{op},{name},"
                    f"{nbytes},{secs:.3f},{mbps:.2f}\n")


# --------------------------------------------------------- authentication
def authenticate(conn):
    """Challenge-response: the password never travels over the network."""
    msg = recv_msg(conn)
    if msg.get("cmd") != "LOGIN":
        return None
    name = str(msg.get("user", ""))
    rec = users.get(name)
    nonce = secrets.token_bytes(16)
    # unknown user gets a fake salt so we do not reveal which users exist
    salt = bytes.fromhex(rec["salt"]) if rec else secrets.token_bytes(16)
    send_msg(conn, {"salt": salt.hex(), "nonce": nonce.hex()})
    proof = str(recv_msg(conn).get("proof", ""))
    if rec:
        expected = hmac.new(bytes.fromhex(rec["key"]), nonce, "sha256").hexdigest()
        if hmac.compare_digest(expected, proof):
            send_msg(conn, {"ok": True, "role": rec["role"]})
            return name, rec["role"]
    send_msg(conn, {"ok": False, "error": "authentication failed"})
    return None


# -------------------------------------------------------------- commands
def do_upload(conn, user, role, ip, msg):
    name, size = str(msg.get("name", "")), msg.get("size")
    if not NAME_RE.match(name):
        return send_msg(conn, {"ok": False, "error": "invalid file name"}) or False
    if not isinstance(size, int) or size < 0 or size > MAX_FILE_SIZE:
        return send_msg(conn, {"ok": False, "error": "invalid size"}) or False
    with meta_lock:
        old = metadata.get(name)
    if old and old["owner"] != user and role != "admin":
        return send_msg(conn, {"ok": False, "error": "file owned by " + old["owner"]}) or False

    send_msg(conn, {"ok": True})                      # ready, send the bytes
    tmp = os.path.join(STORAGE, f".{uuid.uuid4().hex}.tmp")
    h, got, t0 = hashlib.sha256(), 0, time.time()
    try:
        with open(tmp, "wb") as f:
            while got < size:
                chunk = conn.recv(min(CHUNK, size - got))
                if not chunk:
                    raise ConnectionError("client dropped during upload")
                f.write(chunk)
                h.update(chunk)
                got += len(chunk)
        secs = time.time() - t0
        digest = h.hexdigest()
        if msg.get("sha256") and msg["sha256"] != digest:
            os.remove(tmp)
            send_msg(conn, {"ok": False, "error": "checksum mismatch"})
            return True
        with meta_lock:                                # commit atomically
            os.replace(tmp, os.path.join(STORAGE, name))
            metadata[name] = {"owner": user, "size": size, "sha256": digest,
                              "uploaded": time.strftime("%Y-%m-%d %H:%M:%S"),
                              "downloads": metadata.get(name, {}).get("downloads", 0)}
            save_metadata()
        log_transfer(user, ip, "UPLOAD", name, size, secs)
        send_msg(conn, {"ok": True, "sha256": digest})
        return True
    except Exception:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def do_download(conn, user, role, ip, msg):
    name = str(msg.get("name", ""))
    with meta_lock:
        info = dict(metadata.get(name, {}))
    if not info or not NAME_RE.match(name):
        return send_msg(conn, {"ok": False, "error": "no such file"})
    send_msg(conn, {"ok": True, "size": info["size"], "sha256": info["sha256"]})
    t0 = time.time()
    with open(os.path.join(STORAGE, name), "rb") as f:
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            conn.sendall(chunk)
    log_transfer(user, ip, "DOWNLOAD", name, info["size"], time.time() - t0)
    with meta_lock:
        if name in metadata:
            metadata[name]["downloads"] += 1
            save_metadata()


def do_list(conn, *_):
    with meta_lock:
        files = [{"name": n, **m} for n, m in sorted(metadata.items())]
    send_msg(conn, {"ok": True, "files": files})


def do_delete(conn, user, role, ip, msg):
    name = str(msg.get("name", ""))
    with meta_lock:
        info = metadata.get(name)
        if not info:
            return send_msg(conn, {"ok": False, "error": "no such file"})
        if info["owner"] != user and role != "admin":
            return send_msg(conn, {"ok": False, "error": "not your file"})
        del metadata[name]
        save_metadata()
        try:
            os.remove(os.path.join(STORAGE, name))
        except FileNotFoundError:
            pass
    log.info("DELETE %s by %s", name, user)
    send_msg(conn, {"ok": True})


HANDLERS = {"UPLOAD": do_upload, "DOWNLOAD": do_download,
            "LIST": do_list, "DELETE": do_delete}


# ---------------------------------------------------------- per-client thread
def handle_client(conn, addr):
    ip = addr[0]
    conn.settimeout(60)
    who = "?"
    try:
        auth = authenticate(conn)
        if not auth:
            log.warning("auth failed from %s", ip)
            return
        user, role = auth
        who = user
        log.info("%s logged in from %s (%s) [%s]", user, ip, role,
                 threading.current_thread().name)
        while True:
            msg = recv_msg(conn)
            cmd = msg.get("cmd")
            if cmd == "QUIT":
                break
            if cmd not in HANDLERS:
                send_msg(conn, {"ok": False, "error": "unknown command"})
            elif cmd not in ROLES[role]:
                log.warning("DENIED %s for %s (%s)", cmd, user, role)
                send_msg(conn, {"ok": False, "error": f"role '{role}' may not {cmd}"})
            else:
                HANDLERS[cmd](conn, user, role, ip, msg)
    except (ConnectionError, socket.timeout, ValueError):
        log.info("connection from %s (%s) ended", ip, who)
    except Exception:
        log.exception("error with client %s", ip)
    finally:
        conn.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=SERVICE_PORT)
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s",
                        datefmt="%H:%M:%S",
                        handlers=[logging.StreamHandler(), logging.FileHandler("server.log")])
    os.makedirs(STORAGE, exist_ok=True)
    load_users()
    load_metadata()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(64)
    log.info("file server listening on %s:%d", args.host, args.port)
    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle_client, args=(conn, addr),
                             daemon=True).start()
    except KeyboardInterrupt:
        log.info("shutting down")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
