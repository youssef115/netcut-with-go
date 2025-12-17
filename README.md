# NetCut Pro (Go)

A network management and analysis tool written in Go using Fyne and Gopacket.

## Prerequisites

Before building or running the application, ensure you have the following installed:

1.  **Go**: [Download Go](https://go.dev/dl/) (version 1.24 or later recommended).
2.  **C Compiler (GCC)**: Required for CGo.
    *   **Windows**: Install [TDM-GCC](https://jmeubank.github.io/tdm-gcc/) or similar.
    *   **Linux**: `sudo apt install build-essential`
3.  **Packet Capture Driver**:
    *   **Windows**: Install [Npcap](https://npcap.com/) (ensure "Install Npcap in WinPcap API-compatible Mode" is selected during installation) or WinPcap.
    *   **Linux**: `sudo apt install libpcap-dev`

## Build

1.  Open a terminal in the project directory.
2.  Run the build command:

    ```bash
    go build -v -o NetCut.exe main.go
    ```

## Run

**Important**: This application performs low-level network operations (ARP spoofing, packet capture) and **requires Administrator (Root) privileges**.

### Windows
Right-click `NetCut.exe` and select **"Run as Administrator"**.

### Linux
Run with `sudo`:

```bash
sudo -E ./NetCut
```

## Features

*   **Scan**: Discover devices on your local network.
*   **Identify**: Shows IP, MAC, Vendor, and Hostname.
*   **Cut Internet**: Block internet access for specific devices.
*   **Limit Speed**: Throttle bandwidth for specific devices.
*   **Sniff Traffic**: Monitor visited websites (DNS) and bandwidth usage for a target device without cutting their connection. Includes "Burst" mode for fast activation.

## Disclaimer

This tool is for educational and network administration purposes only. Use only on networks you own or have permission to manage.
