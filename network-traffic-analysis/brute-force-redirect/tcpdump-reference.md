# tcpdump: Essential Concepts and Commands

A working reference for capturing and reading network traffic with tcpdump, built while investigating the incidents in this portfolio section.

## What tcpdump does

tcpdump is a command-line packet capture and analysis tool for Linux and Unix-like systems. It captures traffic passing through a network interface and prints (or saves) a readable summary of each packet, making it useful for troubleshooting connectivity issues and investigating security incidents, especially on remote servers or headless systems where a GUI tool like Wireshark isn't available.

## Checking installation and interfaces

| Purpose | Command |
|---|---|
| Check if tcpdump is installed | `which tcpdump` |
| Install on Red Hat/CentOS | `sudo dnf install -y tcpdump` |
| List available capture interfaces | `sudo tcpdump -D` |

## Basic capture

| Purpose | Command |
|---|---|
| Capture on all interfaces | `sudo tcpdump -i any` |
| Capture on a specific interface | `sudo tcpdump -i eth0` |
| Limit to N packets, then stop | `sudo tcpdump -i any -c 5` |
| Skip DNS/hostname resolution | `sudo tcpdump -i any -n` |
| Skip hostname *and* port name resolution | `sudo tcpdump -i any -nn` |

`-nn` is worth defaulting to during troubleshooting: it shows raw IPs and port numbers instead of resolved names, which is both faster and clearer when tracing a specific incident.

## Filtering traffic

tcpdump's filter expressions (technically BPF syntax) let you narrow a capture down to only what's relevant.

| Filter type | Example | Effect |
|---|---|---|
| By protocol | `tcpdump -i any icmp` | Only ICMP (ping) traffic |
| By host | `tcpdump -i any -nn host 203.0.113.2` | Only traffic to/from that IP |
| By port | `tcpdump -i any -nn port 80` | Only traffic on port 80 (HTTP) |
| By source | `tcpdump -i any -nn src 192.168.1.5` | Only traffic originating from that IP |
| By destination | `tcpdump -i any -nn dst 192.168.1.5` | Only traffic addressed to that IP |
| Combined (AND) | `tcpdump -nn src 192.168.1.5 and port 80` | Source IP *and* port together |
| Combined (OR, grouped) | `tcpdump -nn "port 80 and (src A or src B)"` | Either source, same port |
| By TCP flag | `tcpdump 'tcp[tcpflags] == tcp-syn'` | Only SYN packets |

Quoting a filter expression (`"..."`) is necessary whenever it contains parentheses, so the shell doesn't try to interpret them itself.

## Reading a captured packet

A typical TCP line looks like this:

```
14:18:36.786501 IP your.machine.36086 > yummyrecipesforme.com.http: Flags [S], seq 2873951608, win 65495, length 0
```

| Field | Meaning |
|---|---|
| `14:18:36.786501` | Timestamp of the packet |
| `IP` | Network-layer protocol (IPv4; IPv6 shows as `IP6`) |
| `your.machine.36086` | Source IP address and port |
| `yummyrecipesforme.com.http` | Destination IP/hostname and port. Note: `.http` and `.domain` are tcpdump's name for well-known ports (80 and 53), not a separate protocol label — the real protocol is indicated separately, either by the TCP flags or by an explicit protocol tag like `HTTP:` |
| `Flags [S]` | TCP flag(s) on this packet (see table below) |
| `seq` | Sequence number, the byte range this packet covers in the data stream |
| `ack` | Acknowledgment number, the next byte the sender expects to receive |
| `win` | Window size, receive buffer space available |
| `length` | Payload length in bytes |

## TCP flags reference

| Flag | Meaning | Notes |
|---|---|---|
| `S` | SYN | Initiates a new connection |
| `S.` | SYN-ACK | Server's reply to a SYN, acknowledging and continuing the handshake |
| `.` | ACK | Acknowledgment, no new data |
| `P.` | PSH-ACK | Data being pushed to the application layer (e.g., an HTTP request) |
| `F.` | FIN-ACK | Graceful connection close |
| `R.` | RST-ACK | Abrupt connection reset |

A normal TCP connection setup appears as three consecutive lines: `[S]` from the client, `[S.]` from the server, `[.]` from the client, completing the three-way handshake before any application data (like an HTTP GET request) is sent.

## Inspecting packet content

| Purpose | Command |
|---|---|
| Show payload in ASCII | `sudo tcpdump -i any -A port 80` |
| Show payload in hex and ASCII | `sudo tcpdump -i any -X port 80` |

This is useful for reading plaintext protocols like HTTP directly, though it won't reveal anything meaningful for encrypted traffic (HTTPS, TLS, etc.).

## Saving and replaying captures

| Purpose | Command |
|---|---|
| Save capture to a file | `sudo tcpdump -i any -w capture.pcap` |
| Read a saved capture | `tcpdump -nn -r capture.pcap` |
| Filter while reading a saved capture | `tcpdump -nn -r capture.pcap src 203.0.113.2` |

Saved `.pcap` files can also be opened in Wireshark for a graphical view of the same data, which is useful when a capture needs to be reviewed in more visual detail after the fact.

## Sources
- Gerardi, R. *An introduction to using tcpdump at the Linux command line.* Opensource.com.
- Comparitech. *tcpdump Cheat Sheet.*
