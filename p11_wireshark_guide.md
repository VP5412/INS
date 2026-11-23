# Practical 11 — Study and use the open-source packet analyzer Wireshark to understand the security mechanism of various network protocols

**Companion program (optional):** `p12_tls_inspect.py` shows the TLS version and cipher suite you
will see in Wireshark.

## 1. Aim
To capture network traffic with **Wireshark** and compare the security of plain-text protocols
(HTTP, FTP, Telnet) with protected ones (HTTPS/TLS, SSH).

## 2. Theory (about 10 lines)
Wireshark is a free, open-source **packet analyzer (sniffer)**. It puts the network card into
*promiscuous / monitor mode* (using libpcap / Npcap), copies every frame that passes the interface and
dissects it layer by layer: Ethernet (frame) → IP (packet) → TCP/UDP (segment) → application
protocol. Captures are saved as `.pcap/.pcapng` files. Two kinds of filters exist:
**capture filters** (BPF syntax, e.g. `port 80`, chosen before capturing) and **display filters**
(Wireshark syntax, e.g. `http`, applied after capturing). Because Wireshark shows raw bytes it
proves *why* encryption is needed: a protocol that sends data in clear text (HTTP, FTP, Telnet,
SMTP, POP3) exposes user names, passwords and content to any sniffer on the path, while TLS and SSH
encrypt the payload so only the handshake and metadata remain visible.

## 3. Requirements
* Wireshark from https://www.wireshark.org/download.html (Windows needs the bundled **Npcap**).
* An internet connection, and a test site/server you are **allowed** to test.
  Use only your own network or sites meant for testing (e.g. `http://testphp.vulnweb.com`,
  `http://neverssl.com`, your college lab server). Do not sniff other people's traffic.

## 4. Steps

### Step 1 – Capture
1. Open Wireshark → choose the active interface (Wi-Fi / Ethernet; the one with moving graph).
2. Optional capture filter: `tcp or udp port 53`. Press the blue shark-fin **Start**.
3. Do the activities below in a browser/terminal, then press the red **Stop** and save
   (`File → Save As → practical11.pcapng`).

### Step 2 – Plain-text protocol: HTTP
1. Open `http://neverssl.com` (or a login form on a test site such as testphp.vulnweb.com).
2. Display filter: `http`. Select the `GET /` and `POST /userinfo.php` packets.
3. **Right-click → Follow → HTTP Stream.** Observe: URL, headers, cookies and, for a POST,
   the **user name and password in readable text**.
4. Filter `http.request.method == "POST"` and open *Hypertext Transfer Protocol → HTML Form URL
   Encoded* to see the fields.

### Step 3 – TCP three-way handshake
Filter `tcp.flags.syn == 1`. See SYN → SYN/ACK → ACK, sequence/ack numbers and window size.
(Security link: SYN flood, TCP session hijacking.)

### Step 4 – DNS
Filter `dns`. Note that queries and answers are plain text (DNS spoofing risk; DoT/DoH encrypt it).

### Step 5 – Encrypted protocol: HTTPS (TLS)
1. Browse to `https://www.wireshark.org`. Filter: `tls` (older versions: `ssl`).
2. Find **Client Hello** (`tls.handshake.type == 1`): TLS version, random value, list of cipher suites,
   `server_name` (SNI) extension.
3. Find **Server Hello** (`tls.handshake.type == 2`): chosen version and **cipher suite**
   (e.g. `TLS_AES_256_GCM_SHA384`) and, for TLS 1.2, the **Certificate** message
   (issuer, subject, validity, public key).
4. After the handshake all data is `Application Data` — **Follow → TLS Stream shows only
   unreadable bytes.** Compare with Step 2.

### Step 6 – Other protocols (choose at least one)
| Protocol | How to test | Filter | What to observe |
|----------|-------------|--------|-----------------|
| FTP | connect to a test FTP server with `ftp host` | `ftp` | `USER` and `PASS` visible in clear text |
| Telnet | `telnet host` on a lab machine | `telnet` | every keystroke is visible |
| SSH | `ssh user@host` | `ssh` | version banner and key exchange only; payload encrypted |
| ICMP | `ping host` | `icmp` | echo request/reply, TTL |

### Step 7 – Useful display filters
`ip.addr == 192.168.1.5`  `tcp.port == 443`  `http contains "password"`  `!(arp or dns)`
`tls.handshake.type == 1`  `frame contains "login"`  `tcp.analysis.retransmission`
Statistics menu: *Protocol Hierarchy*, *Conversations*, *Endpoints*, *I/O Graph*.

## 5. Observation table (fill in from your own capture)
| Protocol | Port | Encrypted? | Sensitive data visible? | Security mechanism / weakness |
|----------|------|-----------|-------------------------|-------------------------------|
| HTTP | 80 | No | URL, cookies, form passwords | none – use HTTPS |
| HTTPS/TLS | 443 | Yes | only IPs, SNI, certificate | TLS handshake, certificates, AEAD cipher |
| FTP | 21 | No | username, password, files | use SFTP/FTPS |
| Telnet | 23 | No | all keystrokes | use SSH |
| SSH | 22 | Yes | only banner, algorithm list | key exchange + MAC + host key |
| DNS | 53 | No | queried domain names | use DNSSEC / DoH |

## 6. Conclusion (sample wording)
Wireshark showed that HTTP, FTP and Telnet transmit credentials as plain text, which any attacker on
the same network can read, whereas HTTPS and SSH negotiate keys in a handshake and encrypt all
application data. Therefore sensitive communication must always use TLS or SSH.

> Add your own screenshots (Follow HTTP Stream with the password, the TLS Client Hello / Server
> Hello, the encrypted Application Data) — captures must be made on your computer.
