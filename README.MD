# 🐾 SniffCLI the E-Waste Sentry

> *"If it works on my machine, it's production ready."*

An extremely minimal, high-performance packet sniffer built with **Go** and **Bubble Tea**. Designed to monitor local network traffic across home lab hardware, from main rigs to aging e-waste.

---

## Notable Features

- **Realtime monitoring** / Captures IPv4, IPv6, ARP, and Ethernet layers.
- **Security alerts** / Built-in detection for potential SSH brute force and unusual outbound ports.
- **Device aliasing** / Map local IPs to friendly names (e.g. `"Main Rig"`, `"My iPhone"`).
- **Aesthetic UI** / A terminal-based interface using `lipgloss`, with a focus on scannability and cleanliness.

---

## Quick Start

If you're on Arch, just make sure you have `libpcap` installed.

```bash
# Install dependencies
go mod download

# Clone the repo and cd into it
git clone https://github.com/hnpf/sniffcli && cd sniffcli

# Build the sentry
go build -o sniffcli

# Give it permissions to sniff without sudo (optional but recommended for multiple uses)
sudo setcap cap_net_raw,cap_net_admin=eip ./sniffcli

# Run it!
./sniffcli
```

---

## Technical Bits

- **Concurrency** / Uses a non-blocking packet source to keep the UI responsive even during traffic spikes.
- **Filtering** / Ignores standard traffic (DNS, HTTPS) to surface generally unusual network behavior.

---

## 📦 Built With

- [Go](https://go.dev/)
- [Bubble Tea](https://github.com/charmbracelet/bubbletea)
- [Lip Gloss](https://github.com/charmbracelet/lipgloss)
- [gopacket](https://github.com/google/gopacket)

## LICENSE
MIT License - This software is provided "as is," without any warranty.
