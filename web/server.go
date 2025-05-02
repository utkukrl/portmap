package web

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/utkukrl/portmap/utils"
)

var templateFile = "templates/template.html"

func StartServer(addr, resultFile string) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		data, err := loadScanResult(resultFile)
		if err != nil {
			http.Error(w, "Failed to load scan results: "+err.Error(), http.StatusInternalServerError)
			return
		}

		t, err := template.ParseFiles(templateFile)
		if err != nil {
			http.Error(w, "Failed to parse template: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if err := t.Execute(w, data); err != nil {
			http.Error(w, "Template execution error: "+err.Error(), http.StatusInternalServerError)
			return
		}
	})

	http.HandleFunc("/raw", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, resultFile)
	})

	log.Printf("🌐 Web server started on http://%s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func loadScanResult(filename string) (map[string][]utils.PortResult, error) {
	file, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var data map[string][]utils.PortResult
	if err := json.Unmarshal(file, &data); err != nil {
		return nil, err
	}
	return data, nil
}
