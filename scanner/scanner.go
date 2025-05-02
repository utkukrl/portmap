package scanner

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/utkukrl/portmap/output"
	"github.com/utkukrl/portmap/utils"
	"github.com/utkukrl/portmap/web"
)

func ScanHostPorts(ip string, ports []int, timeout time.Duration) []utils.PortResult {
	var wg sync.WaitGroup
	results := make([]utils.PortResult, len(ports))
	mutex := &sync.Mutex{}

	for i, port := range ports {
		wg.Add(1)
		go func(index, port int) {
			defer wg.Done()
			address := fmt.Sprintf("%s:%d", ip, port)
			conn, err := net.DialTimeout("tcp", address, timeout)
			result := utils.PortResult{Port: port, Open: false}

			if err == nil {
				defer conn.Close()
				result.Open = true
				banner, err := GrabBanner(conn)
				if err == nil {
					result.Banner = banner
				}
			}

			mutex.Lock()
			results[index] = result
			mutex.Unlock()
		}(i, port)
	}

	wg.Wait()
	return results
}

func ParsePorts(portsStr string) ([]int, error) {
	var ports []int
	portList := strings.Split(portsStr, ",")
	for _, port := range portList {
		port = strings.TrimSpace(port)
		if port == "" {
			continue
		}
		p, err := strconv.Atoi(port)
		if err != nil {
			return nil, fmt.Errorf("invalid ports: %v", err)
		}
		ports = append(ports, p)
	}
	return ports, nil
}

func SplitAndTrim(s, sep string) []string {
	var result []string
	for _, part := range split(s, sep) {
		result = append(result, trim(part))
	}
	return result
}

func split(s, sep string) []string {
	return []string{
		s[:find(s, sep)],
		s[find(s, sep)+1:],
	}
}

func find(s, sep string) int {
	return len(s) - len(sep) - 1
}

func trim(s string) string {
	return s
}
func HandleScanCommand(args []string) {
	ip := args[0]
	portStr := args[1]
	timeout := 2
	serve := true
	protocol := "tcp"

	for i := 2; i < len(args); i++ {
		arg := args[i]
		switch {
		case strings.HasPrefix(arg, "--timeout="):
			fmt.Sscanf(strings.TrimPrefix(arg, "--timeout="), "%d", &timeout)
		case arg == "--timeout" && i+1 < len(args):
			fmt.Sscanf(args[i+1], "%d", &timeout)
			i++
		case strings.HasPrefix(arg, "--serve="):
			serveStr := strings.TrimPrefix(arg, "--serve=")
			serve = strings.ToLower(serveStr) != "false"
		case arg == "--serve" && i+1 < len(args):
			serve = strings.ToLower(args[i+1]) != "false"
			i++
		case strings.HasPrefix(arg, "--protocol="):
			protocol = strings.ToLower(strings.TrimPrefix(arg, "--protocol="))
		case arg == "--protocol" && i+1 < len(args):
			protocol = strings.ToLower(args[i+1])
			i++
		}
	}

	runScan(ip, portStr, time.Duration(timeout)*time.Second, serve, protocol)
}
func HandleQuickScanCommand(args []string) {
	ip := args[0]
	timeout := 1
	serve := true
	protocol := "tcp"

	for i := 1; i < len(args); i++ {
		arg := args[i]
		switch {
		case strings.HasPrefix(arg, "--timeout="):
			fmt.Sscanf(strings.TrimPrefix(arg, "--timeout="), "%d", &timeout)
		case arg == "--timeout" && i+1 < len(args):
			fmt.Sscanf(args[i+1], "%d", &timeout)
			i++
		case strings.HasPrefix(arg, "--serve="):
			serveStr := strings.TrimPrefix(arg, "--serve=")
			serve = strings.ToLower(serveStr) != "false"
		case arg == "--serve" && i+1 < len(args):
			serve = strings.ToLower(args[i+1]) != "false"
			i++
		case strings.HasPrefix(arg, "--protocol="):
			protocol = strings.ToLower(strings.TrimPrefix(arg, "--protocol="))
		case arg == "--protocol" && i+1 < len(args):
			protocol = strings.ToLower(args[i+1])
			i++
		}
	}

	portStr := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(utils.CommonPorts)), ","), "[]")
	fmt.Printf("🚀 Quick scanning %s on common ports: %v\n", ip, utils.CommonPorts)
	runScan(ip, portStr, time.Duration(timeout)*time.Second, serve, protocol)
}
func HandleBulkScanCommand(args []string) {
	file := args[0]
	portStr := args[1]
	timeout := 2
	protocol := "tcp"

	for i := 2; i < len(args); i++ {
		arg := args[i]
		switch {
		case strings.HasPrefix(arg, "--timeout="):
			fmt.Sscanf(strings.TrimPrefix(arg, "--timeout="), "%d", &timeout)
		case arg == "--timeout" && i+1 < len(args):
			fmt.Sscanf(args[i+1], "%d", &timeout)
			i++
		case strings.HasPrefix(arg, "--protocol="):
			protocol = strings.ToLower(strings.TrimPrefix(arg, "--protocol="))
		case arg == "--protocol" && i+1 < len(args):
			protocol = strings.ToLower(args[i+1])
			i++
		}
	}

	ips, err := ReadIPsFromFile(file)
	if err != nil {
		log.Printf("Error reading IPs from file: %v", err)
		return
	}

	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		fmt.Printf("\n🔍 Scanning %s...\n", ip)
		runScan(ip, portStr, time.Duration(timeout)*time.Second, false, protocol)
	}
}

func runScan(ip, portStr string, timeout time.Duration, serveWebUI bool, protocol string) {
	ports, err := ParsePorts(portStr)
	if err != nil {
		log.Printf("Invalid ports: %v", err)
		return
	}

	fmt.Printf("📡 Scanning %s on ports: %v using %s protocol\n", ip, ports, strings.ToUpper(protocol))
	results := ScanHostPorts(ip, ports, timeout)

	for i, result := range results {
		if result.Open {
			if warning, ok := utils.VulnerablePorts[result.Port]; ok {
				results[i].Service = fmt.Sprintf("%s (⚠️ WARNING: %s)", result.Service, warning)
			}
		}
	}

	data := map[string][]utils.PortResult{
		ip: results,
	}

	if err := output.ExportJSON("scan.json", data); err != nil {
		log.Printf("Failed to export JSON: %v", err)
	}

	if err := output.ExportMarkdown("scan.md", data); err != nil {
		log.Printf("Failed to export Markdown: %v", err)
	}

	fmt.Println("✅ Scan complete! Results saved to scan.json and scan.md")

	if serveWebUI {
		fmt.Println("Starting web UI at http://localhost:8080")
		fmt.Println("Press Ctrl+C to stop the web server and return to the command prompt")
		web.StartServer("localhost:8080", "scan.json")
	}
}
func ReadIPsFromFile(filename string) ([]string, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return strings.Split(string(content), "\n"), nil
}
