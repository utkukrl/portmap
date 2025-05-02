package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/c-bata/go-prompt"
	"github.com/spf13/cobra"
	"github.com/utkukrl/portmap/output"
	"github.com/utkukrl/portmap/scanner"
	"github.com/utkukrl/portmap/utils"
	"github.com/utkukrl/portmap/web"
)

var (
	commonPorts     = []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5900, 8080}
	vulnerablePorts = map[int]string{
		21:   "FTP - File Transfer Protocol (insecure, consider SFTP/SCP)",
		23:   "Telnet (insecure, use SSH instead)",
		135:  "Windows RPC (potential security risk)",
		139:  "NetBIOS (potential security risk)",
		445:  "SMB (potential security risk, vulnerable to attacks like EternalBlue)",
		3389: "RDP - Remote Desktop Protocol (secure it with strong passwords/2FA)",
		5900: "VNC (insecure without proper encryption)",
	}
)

var rootCmd = &cobra.Command{
	Use:   "portmap",
	Short: "PortMap Scanner - A tool for scanning ports on target hosts",
	Long: `A flexible port scanner tool that allows you to check for open ports on target IPs.
Results can be exported to JSON and Markdown files, and viewed through a web interface.`,
	Run: func(cmd *cobra.Command, args []string) {
		startInteractiveShell()
	},
}

var scanCmd = &cobra.Command{
	Use:   "scan [ip] [ports]",
	Short: "Scan ports on a target host",
	Long: `Scan specified ports on a target host.
	
Examples:
  portmap scan 192.168.1.1 22,80,443
  portmap scan google.com 80,443 --timeout 5 --serve=false --protocol udp
  portmap scan 192.168.1.1 1-1000 (scan ports 1 to 1000)`,
	Args: cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		ip := args[0]
		portStr := args[1]

		timeout, _ := cmd.Flags().GetInt("timeout")
		serve, _ := cmd.Flags().GetBool("serve")
		protocol, _ := cmd.Flags().GetString("protocol")

		runScan(ip, portStr, time.Duration(timeout)*time.Second, serve, protocol)
	},
}

var quickScanCmd = &cobra.Command{
	Use:   "quickscan [ip]",
	Short: "Quick scan common ports on a target host",
	Long: `Scan commonly used ports on a target host quickly.
	
Examples:
  portmap quickscan 192.168.1.1
  portmap quickscan google.com --timeout 2 --serve=true`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ip := args[0]
		portStr := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(commonPorts)), ","), "[]")

		timeout, _ := cmd.Flags().GetInt("timeout")
		serve, _ := cmd.Flags().GetBool("serve")
		protocol, _ := cmd.Flags().GetString("protocol")

		fmt.Printf("🚀 Quick scanning %s on common ports: %v\n", ip, commonPorts)
		runScan(ip, portStr, time.Duration(timeout)*time.Second, serve, protocol)
	},
}

var bulkScanCmd = &cobra.Command{
	Use:   "bulk [file] [ports]",
	Short: "Scan ports on multiple IPs from a file",
	Long: `Scan specified ports on multiple IPs listed in a file (one IP per line).
	
Examples:
  portmap bulk ips.txt 22,80,443
  portmap bulk ips.txt 1-100 --timeout 3 --protocol tcp`,
	Args: cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		file := args[0]
		portStr := args[1]

		timeout, _ := cmd.Flags().GetInt("timeout")
		protocol, _ := cmd.Flags().GetString("protocol")

		ips, err := scanner.ReadIPsFromFile(file)
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
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(quickScanCmd)
	rootCmd.AddCommand(bulkScanCmd)

	scanCmd.Flags().IntP("timeout", "t", 2, "Timeout per port in seconds")
	scanCmd.Flags().BoolP("serve", "s", true, "Start web UI after scan")
	scanCmd.Flags().StringP("protocol", "p", "tcp", "Protocol to use (tcp or udp)")

	quickScanCmd.Flags().IntP("timeout", "t", 1, "Timeout per port in seconds")
	quickScanCmd.Flags().BoolP("serve", "s", true, "Start web UI after scan")
	quickScanCmd.Flags().StringP("protocol", "p", "tcp", "Protocol to use (tcp or udp)")

	bulkScanCmd.Flags().IntP("timeout", "t", 2, "Timeout per port in seconds")
	bulkScanCmd.Flags().StringP("protocol", "p", "tcp", "Protocol to use (tcp or udp)")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func startInteractiveShell() {
	fmt.Println("Welcome to PortMap")
	fmt.Println("Type 'exit' to quit, 'help' for available commands")
	fmt.Println("-----------------------------------------")

	p := prompt.New(
		executor,
		completer,
		prompt.OptionPrefix("> "),
		prompt.OptionTitle("PortMap Scanner"),
	)
	p.Run()
}

func executor(input string) {
	input = strings.TrimSpace(input)
	if input == "" {
		return
	}

	if input == "exit" {
		fmt.Println("Exiting... Goodbye!")
		os.Exit(0)
		return
	}

	if input == "help" {
		fmt.Println("\nAvailable Commands:")
		fmt.Println("  scan <ip> <ports> [--timeout <seconds>] [--serve <true|false>] [--protocol <tcp|udp>]")
		fmt.Println("    Example: scan 192.168.1.1 22,80,443 --timeout 3 --serve=false --protocol udp")
		fmt.Println()
		fmt.Println("  quickscan <ip> [--timeout <seconds>] [--serve <true|false>] [--protocol <tcp|udp>]")
		fmt.Println("    Example: quickscan 192.168.1.1 --timeout 1")
		fmt.Println()
		fmt.Println("  bulk <file> <ports> [--timeout <seconds>] [--protocol <tcp|udp>]")
		fmt.Println("    Example: bulk ips.txt 22,80,443 --timeout 2")
		fmt.Println()
		fmt.Println("  help - Show this help message")
		fmt.Println("  exit - Exit the application")
		return
	}

	args := strings.Fields(input)
	if len(args) == 0 {
		return
	}

	switch args[0] {
	case "scan":
		if len(args) < 3 {
			fmt.Println("Usage: scan <ip> <ports> [--timeout <seconds>] [--serve <true|false>] [--protocol <tcp|udp>]")
			fmt.Println("Example: scan 192.168.1.1 22,80,443 --timeout 3 --serve=false --protocol udp")
			return
		}
		scanner.HandleScanCommand(args[1:])
	case "quickscan":
		if len(args) < 2 {
			fmt.Println("Usage: quickscan <ip> [--timeout <seconds>] [--serve <true|false>] [--protocol <tcp|udp>]")
			fmt.Println("Example: quickscan 192.168.1.1 --timeout 1")
			return
		}
		scanner.HandleQuickScanCommand(args[1:])
	case "bulk":
		if len(args) < 3 {
			fmt.Println("Usage: bulk <file> <ports> [--timeout <seconds>] [--protocol <tcp|udp>]")
			fmt.Println("Example: bulk ips.txt 22,80,443 --timeout 2")
			return
		}
		scanner.HandleBulkScanCommand(args[1:])
	default:
		fmt.Println("Unknown command:", args[0])
		fmt.Println("Type 'help' for available commands")
	}
}

func completer(d prompt.Document) []prompt.Suggest {
	s := []prompt.Suggest{
		{Text: "scan", Description: "Scan ports on a target host"},
		{Text: "quickscan", Description: "Quick scan common ports on a target host"},
		{Text: "bulk", Description: "Scan ports on multiple IPs from a file"},
		{Text: "help", Description: "Show help information"},
		{Text: "exit", Description: "Exit the application"},
	}
	return prompt.FilterHasPrefix(s, d.GetWordBeforeCursor(), true)
}

func runScan(ip, portStr string, timeout time.Duration, serveWebUI bool, protocol string) {
	ports, err := scanner.ParsePorts(portStr)
	if err != nil {
		log.Printf("Invalid ports: %v", err)
		return
	}

	fmt.Printf("📡 Scanning %s on ports: %v using %s protocol\n", ip, ports, strings.ToUpper(protocol))
	results := scanner.ScanHostPorts(ip, ports, timeout)

	for i, result := range results {
		if result.Open {
			if warning, ok := vulnerablePorts[result.Port]; ok {
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
