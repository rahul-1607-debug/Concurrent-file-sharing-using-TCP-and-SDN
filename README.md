# Concurrent File Sharing System (TCP + SDN)

A concurrent file-sharing system built using Python TCP sockets and Software-Defined Networking (SDN). The system supports multiple simultaneous file transfers, secure authentication, role-based access control, file integrity verification, bandwidth monitoring, and network-level access policies.

## 1. Features

- **Concurrent TCP File Transfers:** Supports multiple clients simultaneously using multithreading.
- **File Upload and Download:** Transfers files in 64 KB chunks for efficient memory usage.
- **File Metadata Management:** Maintains file owner, size, SHA-256 checksum, upload timestamp, and download count.
- **Secure Authentication:** Implements challenge-response authentication using PBKDF2 and HMAC.
- **Role-Based Access Control:** Supports Admin, User, and Read-only roles.
- **SDN-Based Access Policies:** Blocks selected hosts and applies bandwidth restrictions using OpenFlow meters.
- **Bandwidth Monitoring:** Tracks network traffic and calculates bandwidth usage per connection and client.
- **File Integrity Verification:** Uses SHA-256 checksums to verify transferred files.
- **Concurrent Transfer Testing:** Supports simultaneous upload and download testing.

## 2. System Architecture

```text
 h2 (bob)  ─┐
 h3 (carol)─┼── s1 (Open vSwitch) ── h1: File Server
 h4 (guest)─┘        │                 TCP Port: 9000
                     │
              Ryu SDN Controller
              - Traffic Forwarding
              - Access Policies
              - Bandwidth Monitoring
```

The system operates through two independent control layers:

**Application Layer (`server.py`)**
- User authentication
- Role-based permissions
- File ownership and access control
- Upload and download management

**Network Layer (`sdn_controller.py`)**
- Host blocking
- Bandwidth rate limiting
- Traffic monitoring
- OpenFlow rule management

## 3. Protocol Design

The system uses TCP sockets for communication.

Since TCP provides a continuous byte stream rather than individual messages, a length-prefixed framing mechanism is implemented.

Message format:

```text
[4-byte message length][JSON message]
```

File data is transferred as raw bytes after the initial metadata exchange.

**Upload Process:**
1. Client sends an UPLOAD request containing the filename, file size, and SHA-256 checksum.
2. Server validates the request and responds.
3. Client streams the file in chunks.
4. Server verifies the checksum and stores the completed file.
5. Server updates the metadata.

**Download Process:**
1. Client sends a DOWNLOAD request.
2. Server responds with file size and checksum.
3. Server streams the file to the client.
4. Client verifies the downloaded file using SHA-256.

## 4. Concurrency and Thread Safety

The server uses a thread-per-client architecture.

- Each client connection is handled by an independent thread.
- Slow clients do not block other active connections.
- A mutex (`meta_lock`) protects shared metadata from race conditions.
- Files are initially written to temporary files.
- `os.replace()` moves completed and verified files into their final location.
- Data is streamed in chunks, keeping memory consumption independent of file size.

Alternative concurrency approaches include:
- `ThreadPoolExecutor`
- `asyncio`
- `selectors`

## 5. Authentication and Access Control

The authentication system uses PBKDF2-HMAC-SHA256 and challenge-response verification.

**Security mechanisms:**
- Passwords are not stored directly.
- Password-derived keys are generated using PBKDF2 with a unique salt and 100,000 iterations.
- HMAC-based challenge-response authentication prevents passwords from being transmitted directly.
- Random nonces help prevent replay attacks.
- Unknown usernames receive a fake salt to reduce username enumeration.
- File names are validated to prevent path traversal attacks.

**User Roles:**

| Role | Permissions |
|---|---|
| Admin | Full access |
| User | Upload, download, and list files |
| Read-only | Download and list files |

File deletion is restricted to the file owner or an administrator.

**Default Test Accounts:**

| Username | Password | Role |
|---|---|---|
| alice | alice123 | Admin |
| bob | bob123 | User |
| carol | carol123 | User |
| guest | guest123 | Read-only |

*Security Note:* File contents are not encrypted during transmission. TLS should be implemented for secure deployment.

## 6. Software-Defined Networking (SDN)

The SDN implementation uses:

- **Controller:** Ryu / OS-Ken
- **Protocol:** OpenFlow 1.3
- **Virtual Switch:** Open vSwitch
- **Network Emulator:** Mininet

### 6.1 Learning Switch

The controller learns MAC addresses and their corresponding switch ports.

It installs forwarding rules so subsequent packets can be handled directly by the switch.

### 6.2 Host Blocking

Selected hosts can be denied access to the file-sharing service using high-priority OpenFlow rules.

For example, h4 is blocked from accessing the server on TCP port 9000 while other network communication remains available.

### 6.3 Bandwidth Rate Limiting

OpenFlow meters enforce bandwidth restrictions.

For example, h3 can be configured with a 5 Mbps bandwidth limit.

The switch enforces the restriction using a meter with a drop band.

### 6.4 Bandwidth Monitoring

The controller periodically requests flow statistics from the switch using `OFPFlowStatsRequest`.

Bandwidth is calculated using changes in byte counters over time:

```text
Mbps = (Change in bytes × 8) / (Time interval × 1,000,000)
```

Monitoring information is displayed in the controller logs and saved to `sdn_bandwidth.csv`.

Policies can be configured using:

- `BLOCKED_HOSTS`
- `RATE_LIMITS_KBPS`

## 7. Technologies Used

| Technology | Purpose |
|---|---|
| Python | Server, client, and controller implementation |
| TCP Sockets | Reliable network communication |
| Multithreading | Concurrent client handling |
| JSON | Message framing and metadata storage |
| SHA-256 | File integrity verification |
| PBKDF2 and HMAC | Authentication |
| Ryu / OS-Ken | SDN controller |
| OpenFlow 1.3 | Network flow management |
| Open vSwitch | Software-based switching |
| Mininet | Virtual network topology |

## 8. Installation and Execution

### A. Functional Testing (Without SDN)

Start the server:

```bash
python3 server.py
```

Run concurrent transfer tests:

```bash
python3 test_concurrent.py -n 6 --size 20
```

List available files:

```bash
python3 client.py -u bob -p bob123 list
```

Upload a file:

```bash
python3 client.py -u bob -p bob123 upload myfile.pdf
```

Download a file:

```bash
python3 client.py -u guest -p guest123 download myfile.pdf -o /tmp
```

### B. SDN Experiment (Ubuntu with Mininet)

Install the required dependencies:

```bash
sudo apt install mininet openvswitch-switch
pip install ryu
```

**Terminal 1 – Start the SDN Controller**

```bash
ryu-manager sdn_controller.py
```

**Terminal 2 – Start the Mininet Topology**

```bash
sudo python3 topology.py
```

Inside Mininet:

Start the file server on h1:

```bash
mininet> h1 python3 server.py &
```

Test simultaneous transfers from h2:

```bash
mininet> h2 python3 test_concurrent.py --host 10.0.0.1 -n 3 --size 30
```

Test bandwidth restriction on h3:

```bash
mininet> h3 python3 client.py --host 10.0.0.1 -u carol -p carol123 upload big.bin
```

Test network-level blocking on h4:

```bash
mininet> h4 python3 client.py --host 10.0.0.1 -u guest -p guest123 list
```

Inspect installed OpenFlow rules:

```bash
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1
```

Generate a sample 50 MB file:

```bash
head -c 50M /dev/urandom > big.bin
```

*Note: Ryu may require an older Python environment depending on the installed eventlet version.*

## 9. Performance Testing and Results

The system was tested with multiple simultaneous TCP clients.

**Localhost Test:**
- Number of simultaneous clients: 6
- File size per client: 20 MB
- Successful transfers: 6/6
- SHA-256 integrity verification: Successful for all files
- Observed upload throughput: Approximately 300–450 Mbps
- Observed download throughput: Approximately 150–220 Mbps

**Additional Experiments:**

1. Compare bandwidth with 1, 3, and 6 simultaneous clients.
2. Compare unrestricted transfers with transfers subject to a 5 Mbps meter.
3. Test network-level host blocking.
4. Verify application-level permission restrictions using read-only accounts.
5. Test authentication with incorrect passwords.
6. Inspect OpenFlow rules and bandwidth monitoring logs.

The SDN implementation has been syntax-checked. Full Mininet and Ryu execution and performance measurements should be validated in the target environment.

## 10. Limitations and Future Improvements

- Implement TLS encryption for file transfers.
- Replace JSON-based metadata storage with a database.
- Introduce bounded thread pools for improved scalability.
- Extend monitoring with a graphical dashboard.
- Support multiple switches and more complex network topologies.
- Improve bandwidth allocation and traffic management policies.

## 11. Repository Structure

```text
Concurrent-File-Sharing-System/
│
├── server.py
├── client.py
├── common.py
├── sdn_controller.py
├── topology.py
├── test_concurrent.py
│
├── metadata.json
├── transfers.csv
├── sdn_bandwidth.csv
│
└── README.md
```

*The repository may also contain supporting configuration files, test files, and generated storage directories.*

---

**Concurrent File Sharing System using TCP and Software-Defined Networking (SDN).**
