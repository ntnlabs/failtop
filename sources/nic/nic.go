package nic

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"failtop/state"
)

// IfaceCounters holds raw byte counters from /proc/net/dev.
type IfaceCounters struct {
	RxBytes uint64
	TxBytes uint64
}

// ParseProcNetDev parses the content of /proc/net/dev and returns a map
// of interface name → counters.
func ParseProcNetDev(content string) (map[string]IfaceCounters, error) {
	result := make(map[string]IfaceCounters)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		fields := strings.Fields(parts[1])
		if len(fields) < 9 {
			continue
		}
		rx, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		tx, err := strconv.ParseUint(fields[8], 10, 64)
		if err != nil {
			continue
		}
		result[name] = IfaceCounters{RxBytes: rx, TxBytes: tx}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("no interfaces found in /proc/net/dev")
	}
	return result, nil
}

// DetectInterface returns the first non-loopback interface from the map.
func DetectInterface(ifaces map[string]IfaceCounters) string {
	for name := range ifaces {
		if name != "lo" {
			return name
		}
	}
	return ""
}

// fetchPublicIP fetches the public IP from the given URL (plain text body).
// Returns "" on any error or if url is "off".
func fetchPublicIP(url string) string {
	if url == "" || url == "off" {
		return ""
	}
	client := http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("User-Agent", "failtop/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return ""
	}
	ip := strings.TrimSpace(string(body))
	// Reject HTML or anything that doesn't look like an IP address
	if strings.ContainsAny(ip, "<> \t\n") || len(ip) > 45 {
		return ""
	}
	return ip
}

// localIP returns the first non-loopback IPv4 address for the named interface.
func localIP(ifaceName string) string {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return ""
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.IsLoopback() {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String()
		}
	}
	return ""
}

// Run starts the NIC polling goroutine. Samples /proc/net/dev every second,
// computes rates, and updates st. Blocks until done is closed.
func Run(ifaceOverride string, publicIPURL string, st *state.AppState, done <-chan struct{}) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return
	}
	ifaces, err := ParseProcNetDev(string(data))
	if err != nil {
		return
	}

	ifaceName := ifaceOverride
	if ifaceName == "" {
		ifaceName = DetectInterface(ifaces)
	}
	if ifaceName == "" {
		return
	}

	pubIP := fetchPublicIP(publicIPURL)
	locIP := localIP(ifaceName)

	st.Lock()
	st.NIC.Interface = ifaceName
	st.NIC.PublicIP = pubIP
	st.NIC.LocalIP = locIP
	st.Unlock()

	prev := ifaces[ifaceName]
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			data, err := os.ReadFile("/proc/net/dev")
			if err != nil {
				continue
			}
			ifaces, err := ParseProcNetDev(string(data))
			if err != nil {
				continue
			}
			curr, ok := ifaces[ifaceName]
			if !ok {
				continue
			}
			rxRate := float64(curr.RxBytes-prev.RxBytes) / 1.0
			txRate := float64(curr.TxBytes-prev.TxBytes) / 1.0
			if rxRate < 0 {
				rxRate = 0
			}
			if txRate < 0 {
				txRate = 0
			}
			prev = curr

			st.Lock()
			st.NIC.RxRate = rxRate
			st.NIC.TxRate = txRate
			st.AppendNICHistory(rxRate, txRate)
			st.Unlock()
		}
	}
}
