# PortMap Scanner 🚀

A powerful and flexible port scanning tool with interactive shell, web interface, and multiple output formats.

## Features ✨

- **Multiple scan modes**:
  - Single target scan
  - Quick scan (common ports)
  - Bulk scan (multiple IPs from file)
- **Interactive shell** with command completion
- **Web interface** to view scan results
- **Multiple output formats**: JSON and Markdown
- **Vulnerability warnings** for known risky ports
- **Protocol support**: TCP and UDP
- **Configurable timeout** per port

## Installation 📦

### Install from source
```bash
git clone https://github.com/utkukrl/portmap.git
cd portmap
go build -o portmap
sudo mv portmap /usr/local/bin/
```

## Usage 🚀

### Interactive Shell

Simply run without arguments to enter interactive REPL:

```bash
portmap
```

Inside the shell, you can run commands like:

```
> quickscan 192.168.1.1
> scan scanme.nmap.org 22,80,443 --timeout 3
> bulk ips.txt --ports 21,22,80,443
> exit
```

### Command-Line Mode

You can also use `portmap` directly with arguments:

#### Quick Scan (Common Ports)

```bash
portmap quickscan 192.168.1.1
```

#### Custom Port Scan

```bash
portmap scan scanme.nmap.org 22,80,443 --timeout 3
```

#### Bulk Scan from File

```bash
portmap bulk targets.txt --ports 21,22,80,443 --timeout 2
```

### Web Interface

After scanning, start the web interface:

Open [http://localhost:8080](http://localhost:8080) to view the results in your browser.

### Help

For all available commands and flags:

```bash
portmap --help
```

Or within the REPL shell:

```
> help
```
