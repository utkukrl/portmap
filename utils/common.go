package utils

var (
	CommonPorts     = []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5900, 8080}
	VulnerablePorts = map[int]string{
		21:   "FTP - File Transfer Protocol (insecure, consider SFTP/SCP)",
		23:   "Telnet (insecure, use SSH instead)",
		135:  "Windows RPC (potential security risk)",
		139:  "NetBIOS (potential security risk)",
		445:  "SMB (potential security risk, vulnerable to attacks like EternalBlue)",
		3389: "RDP - Remote Desktop Protocol (secure it with strong passwords/2FA)",
		5900: "VNC (insecure without proper encryption)",
	}
)
