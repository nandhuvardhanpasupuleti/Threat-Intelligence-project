import psutil
import csv
import time
import datetime

FEATURES = ["cpu_usage","mem_usage","proc_count",
            "net_bytes_sent","net_bytes_recv","disk_read","disk_write"]

def collect_metrics():
    net  = psutil.net_io_counters()
    disk = psutil.disk_io_counters()
    return {
        "timestamp"      : datetime.datetime.now().isoformat(),
        "cpu_usage"      : psutil.cpu_percent(interval=0.5),
        "mem_usage"      : psutil.virtual_memory().percent,
        "proc_count"     : len(psutil.pids()),
        "net_bytes_sent" : net.bytes_sent  if net  else 0,
        "net_bytes_recv" : net.bytes_recv  if net  else 0,
        "disk_read"      : disk.read_bytes  if disk else 0,
        "disk_write"     : disk.write_bytes if disk else 0,
    }

if __name__ == "__main__":
    with open("endpoint_data.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp"]+FEATURES)
        writer.writeheader()
        print("[*] Collecting data... Press Ctrl+C to stop.")
        while True:
            try:
                row = collect_metrics()
                writer.writerow(row)
                f.flush()
                print(f"  CPU:{row['cpu_usage']}%  RAM:{row['mem_usage']}%  Procs:{row['proc_count']}")
                time.sleep(5)
            except KeyboardInterrupt:
                print("\n[*] Done collecting.")
                break
