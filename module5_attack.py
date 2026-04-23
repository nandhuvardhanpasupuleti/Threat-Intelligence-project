"""
Controlled CPU stress to exercise MITRE ATT&CK correlation (demo).

Maps to:
  - T1496 Resource Hijacking — sustained abnormal CPU (mining-like load)
  - T1499 Endpoint Denial of Service — if CPU stays very high (see module3_correlate rules)

The dashboard uses *sustained* CPU (two polls at ~5s), not a single tick — so run long enough
for two /api/metrics samples while this process is active (≥15s recommended).
"""
import multiprocessing
import time

DURATION = 18  # seconds; keep ≥15s so two 5s dashboard polls see sustained load


def controlled_cpu_load():
    end_time = time.time() + DURATION
    # Busy loop (heavier than sqrt-only) so multi-core load shows up as sustained high CPU %
    x = 0
    while time.time() < end_time:
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF


if __name__ == "__main__":
    print("[SIMULATION] MITRE T1496/T1499-style CPU load starting ({}s)...".format(DURATION))

    processes = []
    core_count = max(1, multiprocessing.cpu_count() // 2)

    for _ in range(core_count):
        p = multiprocessing.Process(target=controlled_cpu_load)
        p.start()
        processes.append(p)

    time.sleep(DURATION)

    for p in processes:
        p.terminate()
        p.join(timeout=2)

    print("[SIMULATION] Completed.")