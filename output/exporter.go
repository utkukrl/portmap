package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/utkukrl/portmap/utils"
)

func ExportJSON(filename string, data map[string][]utils.PortResult) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

func ExportMarkdown(filename string, data map[string][]utils.PortResult) error {
	var builder strings.Builder

	builder.WriteString("# PortMap Scan Report\n\n")

	for ip, results := range data {
		builder.WriteString(fmt.Sprintf("## %s\n\n", ip))
		builder.WriteString("| Port | Status | Banner |\n")
		builder.WriteString("|------|--------|--------|\n")
		for _, result := range results {
			status := "Closed"
			if result.Open {
				status = "Open"
			}
			banner := strings.TrimSpace(result.Banner)
			if banner == "" {
				banner = "-"
			}
			builder.WriteString(fmt.Sprintf("| %d | %s | `%s` |\n", result.Port, status, banner))
		}
		builder.WriteString("\n")
	}

	return os.WriteFile(filename, []byte(builder.String()), 0644)
}
