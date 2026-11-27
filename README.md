# Assignment 14 – Concurrent File Sharing System (TCP + SDN)

## 1. What the assignment asks, and where each point is solved

| Requirement | Where / how |
|---|---|
| Concurrent TCP file transfers | `server.py` – `accept()` loop starts **one thread per client** |
| Upload and download | `UPLOAD` / `DOWNLOAD` commands, files streamed in 64 KB chunks |
| Maintain file metadata | `metadata.json` – owner, size, SHA-256, upload time, download count |
| Authenticated access | Challenge-response login (PBKDF2 + HMAC), roles admin/user/readonly |
| Apply SDN access policies | `sdn_controller.py` – block a host, rate-limit a host (OpenFlow meters) |
| Monitor bandwidth | Controller polls flow stats -> Mbps per connection and per client; server also logs `transfers.csv` |
| Test simultaneous transfers | `test_concurrent.py` + parallel clients inside Mininet |

## 2. Architecture

```
 h2 (bob)  ─┐
 h3 (carol)─┼── s1 (Open vSwitch) ── h1: server.py  (TCP :9000)
 h4 (guest)─┘        │
                     └── Ryu controller: forwarding + policies + monitoring
```
Two layers of control:
* **Application layer (server.py)** – *who you are* and *what you may do* (login, roles, file ownership).
* **Network layer (SDN controller)** – *whether your packets are allowed or how fast they go* (drop rules, meters, counters).
They are independent: a host blocked by SDN never even reaches the login prompt.

## 3. Protocol design (common.py)
TCP is a **byte stream**, not messages, so we must frame our own messages:
`[4-byte length][JSON]`, then (for file data) exactly `size` raw bytes. `recv_exact()`
loops until all N bytes arrived, because one `recv()` may return fewer.

Upload: `UPLOAD{name,size,sha256}` -> server `ok` -> client streams bytes -> server `ok{sha256}`.
Download: `DOWNLOAD{name}` -> server `ok{size,sha256}` -> server streams bytes -> client verifies hash.

## 4. Concurrency (how and why it is safe)
* Thread per connection: a slow client blocks only its own thread.
* **Shared state** is the metadata dictionary/file. All reads/writes are inside `meta_lock`
  (a mutex) so two simultaneous uploads cannot corrupt `metadata.json` (race condition).
* Uploads are written to a **temporary file** and `os.replace()`d into place only when complete and
  checksum-verified -> a half-uploaded or dropped file never appears in the listing, and a
  download in progress is not damaged if the file is overwritten (POSIX keeps the old inode open).
* Files are streamed in chunks, so memory use is constant even for 1 GB files.
* Alternatives to mention in your report: `ThreadPoolExecutor` (bounded threads), `asyncio`/`selectors` (event-driven, scales to thousands of clients).

## 5. Authentication and access control
* Passwords are never stored: server keeps `salt` + `PBKDF2-HMAC-SHA256(password, salt, 100000)`.
* Login is **challenge-response**: server sends a random nonce; client answers `HMAC(key, nonce)`.
  The password is never sent, and a replayed answer is useless (new nonce every time).
* Unknown users get a fake salt, so an attacker cannot tell which usernames exist.
* Roles: `admin` (everything), `user` (upload/download/list), `readonly` (download/list).
  Delete only for the file owner or admin.
* File names are whitelisted by regex (blocks `../../etc/passwd` path traversal).
* Default accounts (created on first run): alice/alice123 (admin), bob/bob123, carol/carol123 (user), guest/guest123 (readonly).
* Limitation (state this honestly): file *contents* are not encrypted. Real deployment -> wrap the socket in TLS (`ssl.wrap_socket`).

## 6. SDN part (sdn_controller.py)
Controller = Ryu, protocol = OpenFlow 1.3, switch = Open vSwitch in Mininet.

1. **Learning switch** – packet-in -> remember `mac -> port`, install a flow so later packets stay in the data plane.
2. **Block policy** – at switch connection, install a priority-200 flow matching
   `ipv4_src=h4, ipv4_dst=server, tcp_dst=9000` with **no actions = drop**. (h4 can still ping, only the file service is denied.)
3. **Rate-limit policy** – an OpenFlow **meter** with a *drop band* at 5 Mbps for h3. Flows of h3's file
   transfers reference the meter, so the switch enforces the cap in hardware speed, not the controller.
4. **Monitoring** – for every TCP connection to port 9000 the controller installs its own flow
   (match on full 5-tuple). `OFPFlowStatsRequest` every 2 s returns `byte_count`;
   `Mbps = Δbytes × 8 / Δtime / 1e6`. Results are printed and saved to `sdn_bandwidth.csv`.

Policies are edited at the top of the file (`BLOCKED_HOSTS`, `RATE_LIMITS_KBPS`).

## 7. How to run

**A. Quick functional test, no SDN (any machine):**
```
python3 server.py                                   # terminal 1
python3 test_concurrent.py -n 6 --size 20           # terminal 2
python3 client.py -u bob -p bob123 list
python3 client.py -u bob -p bob123 upload myfile.pdf
python3 client.py -u guest -p guest123 download myfile.pdf -o /tmp
```

**B. Full SDN experiment (Ubuntu with Mininet, Open vSwitch, Ryu):**
```
sudo apt install mininet openvswitch-switch && pip install ryu    # (Ryu may need Python 3.9 or an older eventlet)
# terminal 1
ryu-manager sdn_controller.py
# terminal 2
sudo python3 topology.py
mininet> h1 python3 server.py &
mininet> h2 python3 test_concurrent.py --host 10.0.0.1 -n 3 --size 30   # normal, shows sharing of 100 Mbps link
mininet> h3 python3 client.py --host 10.0.0.1 -u carol -p carol123 upload big.bin   # capped ~5 Mbps
mininet> h4 python3 client.py --host 10.0.0.1 -u guest -p guest123 list             # times out: blocked by SDN
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1          # show your report the installed rules
```
Make a large file first: `head -c 50M /dev/urandom > big.bin`.

## 8. Experiments to put in your report
1. 1 client vs 3 vs 6 simultaneous clients: plot aggregate and per-client Mbps (shows fair sharing).
2. Same upload from h2 (unrestricted) vs h3 (5 Mbps meter): compare times and the controller's BANDWIDTH log.
3. h4 connection attempt: blocked at network layer; contrast with `guest` on h2 who connects but is denied UPLOAD by the server (application layer).
4. Wrong password -> `authentication failed`.
5. Screenshots: `dump-flows`, `sdn_bandwidth.csv` graph, `transfers.csv`.

Result I measured on localhost (6 clients x 20 MB, all simultaneously): 6/6 finished, SHA-256 intact for every file, ~300-450 Mbps up / ~150-220 Mbps down each.
(The SDN files were syntax-checked but need Mininet + Ryu to run; I could not run those here, so test them on your VM and adjust IPs/ports if needed.)

## 9. Likely viva questions
* *Why threads, not processes?* I/O-bound work, shared memory for metadata, cheap to create. (GIL is released during socket I/O.)
* *Why length-prefix?* TCP has no message boundaries.
* *What is a race condition here?* Two uploads updating metadata at once -> lost update; fixed by the lock.
* *Control plane vs data plane?* Controller decides (packet-in, flow-mod); switch forwards by flow table.
* *Reactive vs proactive rules?* Drop/meter rules are proactive (installed at connect); forwarding flows are reactive (on first packet).
* *Why does the meter limit TCP but not break it?* Drops cause TCP congestion control to slow down to the allowed rate.
* *Weakness?* No TLS, thread-per-client limit, single switch, metadata in a JSON file (use a database at scale).
