package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#7D56F4")).
			Padding(0, 1)
	infoStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#04B575")).
			Bold(true)
	alertStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF0000")).
			Bold(true)
	subtleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#626262"))
	knownDevices = map[string]string{
		"127.0.0.1":       "Localhost",
		"192.168.1.1":     "Router",
		"192.168.1.185":   "Main Rig",
		"fe80::1":         "Gateway",
	}
)

type packetInfo struct {
	Timestamp time.Time
	Source    string
	Dest      string
	Proto     string
	Length    int
	Info      string
	IsAlert   bool
}

func formatAddr(addr string) string {
	if name, ok := knownDevices[addr]; ok {
		return name
	}
	return addr
}

func (p packetInfo) String() string {
	timestamp := p.Timestamp.Format("15:04:05")
	src := formatAddr(p.Source)
	dst := formatAddr(p.Dest)
	srcDest := fmt.Sprintf("  %15s -> %-15s", src, dst)
	if p.IsAlert {
		return alertStyle.Render(fmt.Sprintf("[%s] ALERT: %s | %s %s", timestamp, p.Info, srcDest, p.Proto))
	}
	return fmt.Sprintf("[%s] %s | %-4s %d bytes %s", subtleStyle.Render(timestamp), srcDest, infoStyle.Render(p.Proto), p.Length, subtleStyle.Render(p.Info))
}

type model struct {
	viewport      viewport.Model
	packets       []packetInfo
	sshAttempts   map[string]int
	outboundCount int
	ready         bool
	iface         string
	localIPs      map[string]bool
}

type packetMsg packetInfo
func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var (
		cmd  tea.Cmd
		cmds []tea.Cmd
	)
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if k := msg.String(); k == "ctrl+c" || k == "q" {
			return m, tea.Quit
		}

	case tea.WindowSizeMsg:
		headerHeight := 6
		footerHeight := 3
		verticalMarginHeight := headerHeight + footerHeight
		if !m.ready {
			m.viewport = viewport.New(msg.Width, msg.Height-verticalMarginHeight)
			m.viewport.HighPerformanceRendering = false
			m.ready = true
		} else {
			m.viewport.Width = msg.Width
			m.viewport.Height = msg.Height - verticalMarginHeight
		}

	case packetMsg:
		p := packetInfo(msg)
		if p.IsAlert {
			if strings.Contains(p.Info, "SSH") {
				m.sshAttempts[p.Source]++
			} else {
				m.outboundCount++
			}
		}

		m.packets = append(m.packets, p)
		if len(m.packets) > 500 {
			m.packets = m.packets[1:]
		}
		if m.ready {
			var content strings.Builder
			for _, pkg := range m.packets {
				content.WriteString(pkg.String() + "\n")
			}
			m.viewport.SetContent(content.String())
			m.viewport.GotoBottom()
		}
	}

	m.viewport, cmd = m.viewport.Update(msg)
	cmds = append(cmds, cmd)
	return m, tea.Batch(cmds...)
}

func (m model) View() string {
	if !m.ready {
		return "\n  Initializing..."
	}

	header := titleStyle.Render(" SniffCLI ") + " " + subtleStyle.Render("Interface: "+m.iface)
	stats := fmt.Sprintf("\n  Packets: %d | SSH Alerts: %d | Outbound Flags: %d\n", len(m.packets), len(m.sshAttempts), m.outboundCount)
	line := strings.Repeat("─", m.viewport.Width)
	footer := fmt.Sprintf("\n  %s", subtleStyle.Render("press q to quit"))

	return fmt.Sprintf("%s%s\n%s\n%s%s", header, stats, line, m.viewport.View(), footer)
}

func getLocalIPs() map[string]bool {
	ips := make(map[string]bool)
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil {
				ips[ip.String()] = true
			}
		}
	}
	return ips
}

func findBestInterface() string {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "enp6s0" // fallback, personal default.
	}

	for _, d := range devices {
		// here, we skip loopback and interfaces with no addresses
		if len(d.Addresses) > 0 {
			isLoopback := false
			for _, addr := range d.Addresses {
				if addr.IP.IsLoopback() {
					isLoopback = true
					break
				}
			}
			if !isLoopback {
				return d.Name
			}
		}
	}
	return "enp6s0"
}

func isSafePort(port int, isUDP bool) bool {
	safePorts := map[int]bool{
		80:  true, // HTTP
		443: true, // HTTPS
		53:  true, // DNS
		123: true, // NTP
		22:  true, // SSH
	}
	if safePorts[port] {
		return true
	}
	if isUDP && (port == 67 || port == 68 || port == 5353 || port == 1900) {
		return true
	}
	return false
}

func startSniffing(iface string, p *tea.Program) {
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	localIPs := getLocalIPs()
	sshCounters := make(map[string]int)
	for packet := range packetSource.Packets() {
		info := packetInfo{
			Timestamp: time.Now(),
			Length:    len(packet.Data()),
			Proto:     "UNK",
		}
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp, _ := arpLayer.(*layers.ARP)
			info.Proto = "ARP"
			info.Source = net.HardwareAddr(arp.SourceHwAddress).String()
			info.Dest = net.HardwareAddr(arp.DstHwAddress).String()
			info.Info = fmt.Sprintf("Who has %s?", net.IP(arp.DstProtAddress))
		} else if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			info.Source = ip.SrcIP.String()
			info.Dest = ip.DstIP.String()
			info.Proto = "IPv4"
		} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv6)
			info.Source = ip.SrcIP.String()
			info.Dest = ip.DstIP.String()
			info.Proto = "IPv6"
		} else if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
			eth, _ := ethLayer.(*layers.Ethernet)
			info.Proto = "ETH"
			info.Source = eth.SrcMAC.String()
			info.Dest = eth.DstMAC.String()
			info.Info = eth.EthernetType.String()
		}
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			info.Proto = "TCP"
			dstPort := int(tcp.DstPort)
			info.Info = fmt.Sprintf("%d -> %d", tcp.SrcPort, dstPort)

			if dstPort == 22 {
				sshCounters[info.Source]++
				if sshCounters[info.Source] > 3 {
					info.IsAlert = true
					info.Info = "POTENTIAL SSH BRUTE FORCE"
				}
			}

			if localIPs[info.Source] && !isLocalIP(info.Dest) {
				if !isSafePort(dstPort, false) {
					info.IsAlert = true
					info.Info = "UNUSUAL OUTBOUND TCP"
				}
			}
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			info.Proto = "UDP"
			dstPort := int(udp.DstPort)
			info.Info = fmt.Sprintf("%d -> %d", udp.SrcPort, dstPort)

			if localIPs[info.Source] && !isLocalIP(info.Dest) {
				if !isSafePort(dstPort, true) {
					info.IsAlert = true
					info.Info = "UNUSUAL OUTBOUND UDP"
				}
			}
		}

		p.Send(packetMsg(info))
	}
}

func isLocalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return true
	}
	privateRanges := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	for _, r := range privateRanges {
		_, cidr, _ := net.ParseCIDR(r)
		if cidr != nil && cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func main() {
	iface := findBestInterface()
	if len(os.Args) > 1 {
		iface = os.Args[1]
	}

	m := model{
		iface:       iface,
		sshAttempts: make(map[string]int),
		localIPs:    getLocalIPs(),
	}

	p := tea.NewProgram(m, tea.WithAltScreen())

	go startSniffing(iface, p)

	if _, err := p.Run(); err != nil {
		fmt.Printf("Alas, there's been an error: %v", err)
		os.Exit(1)
	}
}
