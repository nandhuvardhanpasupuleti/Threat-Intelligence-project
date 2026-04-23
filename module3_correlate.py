from collections import deque

# Rolling CPU samples (dashboard polls ~5s; 6 samples ≈ 30s) for sustained-load detection.
_cpu_samples = deque(maxlen=6)


def _sustained_cpu(min_len, min_each, min_avg):
    """True if the last `min_len` samples are all >= min_each and average >= min_avg."""
    if len(_cpu_samples) < min_len:
        return False
    tail = list(_cpu_samples)[-min_len:]
    if any(c < min_each for c in tail):
        return False
    return sum(tail) / len(tail) >= min_avg


def _spike_cpu(threshold, consecutive=2):
    """True if the last `consecutive` samples are all at or above threshold."""
    if len(_cpu_samples) < consecutive:
        return False
    tail = list(_cpu_samples)[-consecutive:]
    return all(c >= threshold for c in tail)


def _t1496_resource_hijacking():
    """
    MITRE T1496 (Resource Hijacking): elevated CPU sustained briefly, not a single tick.
    Two consecutive polls (~10s) with mean CPU high enough to catch module5_attack-style runs.
    """
    if len(_cpu_samples) >= 2:
        tail = list(_cpu_samples)[-2:]
        if all(c >= 52 for c in tail) and sum(tail) / 2 >= 62:
            return True
    return _sustained_cpu(3, min_each=48, min_avg=58)


# Static heuristics (optional). Prefer sustained CPU rules to avoid one-sample noise.
ATTACK_RULES = [
    {
        "id": "T1499",
        "name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "condition": lambda m: _spike_cpu(82, consecutive=2) or m.get("cpu_usage", 0) >= 90,
        "risk": 9,
    },
    {
        "id": "T1496",
        "name": "Resource Hijacking",
        "tactic": "Impact",
        "condition": lambda m: _t1496_resource_hijacking(),
        "risk": 8,
    },
    {
        "id": "T1055",
        "name": "Process Injection (Heuristic)",
        "tactic": "Defense Evasion",
        "condition": lambda m: m.get("proc_count", 0) > 700 and m.get("mem_usage", 0) > 90,
        "risk": 7,
    },
    {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel (Heuristic)",
        "tactic": "Exfiltration",
        "condition": lambda m: False,
        "risk": 7,
    },
    {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "condition": lambda m: m.get("proc_count", 0) > 700 and m.get("cpu_usage", 0) > 70,
        "risk": 6,
    },
    {
        "id": "T1082",
        "name": "System Information Discovery (Heuristic)",
        "tactic": "Discovery",
        "condition": lambda m: m.get("proc_count", 0) > 700 and m.get("cpu_usage", 0) > 75,
        "risk": 5,
    },
    {
        "id": "T1083",
        "name": "File and Directory Discovery (Heuristic)",
        "tactic": "Discovery",
        # Disabled — disk_read is cumulative since boot, always huge
        "condition": lambda m: False,
        "risk": 4,
    },
]


def correlate(metrics):
    cpu = float(metrics.get("cpu_usage") or 0)
    _cpu_samples.append(cpu)

    matched = []
    for rule in ATTACK_RULES:
        try:
            if rule["condition"](metrics):
                matched.append({
                    "technique_id":   rule["id"],
                    "technique_name": rule["name"],
                    "tactic":         rule["tactic"],
                    "risk_score":     rule["risk"],
                })
        except Exception:
            continue

    matched.sort(key=lambda x: -x["risk_score"])
    return matched