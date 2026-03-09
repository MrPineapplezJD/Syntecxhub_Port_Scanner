# Python Multi-Threaded Port Scanner

A high-performance TCP port scanner built in Python, designed for educational and learning purposes.  
Scans custom port ranges with adaptive multithreading, grabs service banners, and tracks scan progress in real-time.

---

## Features

- **Custom Port Ranges** – Scan any range from 1 to 65535.  
- **Adaptive Multithreading** – Automatically adjusts threads up to 500 for fast scanning.  
- **Banner Grabbing** – Retrieves service banners to identify open services.  
- **Real-Time Progress Tracking** – Displays how many ports have been scanned.  
- **Result Logging** – Saves scan results and banners to `scan_results.txt`.

---

## Usage

Run the script in Python 3:

```bash
python Port_Scanner.py
```
Enter the host to scan (e.g., scanme.nmap.org).

Enter the start port (e.g., 1).

Enter the end port (e.g., 1000).
