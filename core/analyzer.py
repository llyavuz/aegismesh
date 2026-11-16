import math
import re
from collections import Counter

THREAT_SIGNATURES = {
    "SQL_INJECTION": [
        r"(?i)(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b|\bdrop\b\s+\btable\b|' OR '1'='1|--\s*$)",
    ],
    "XSS_ATTACK": [
        r"(?i)(<script.*?>|javascript:|onerror\s*=|onload\s*=|alert\s*\()",
    ],
    "PATH_TRAVERSAL": [
        r"(\.\./|\.\.\\|/etc/passwd|C:\\Windows\\System32)",
    ],
    "COMMAND_INJECTION": [
        r"(;|\|\||&&)\s*(cat|ls|whoami|wget|curl|nc|bash|powershell)\b",
    ],
    "SENSITIVE_FILE_PROBE": [
        r"(\.env|\.git/config|wp-config\.php|id_rsa|backup\.sql)",
    ]
}

def calculate_shannon_entropy(data: str) -> float:
    """Metnin rastgelelik (şifrelenmiş/obfuscated payload) yoğunluğunu hesaplar."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 2)

def analyze_request(path: str, query: str, user_agent: str, body: str = "") -> dict:
    """Gelen HTTP isteğini analiz eder, tehdit türü, risk skoru (0-100) ve WAF kuralı üretir."""
    full_payload = f"{path} {query} {body}"
    detected_threats = []
    risk_score = 0

    for threat_type, patterns in THREAT_SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, full_payload):
                detected_threats.append(threat_type)
                risk_score += 45
                break

    malicious_agents = ["sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster", "python-requests"]
    if any(agent in user_agent.lower() for agent in malicious_agents):
        detected_threats.append("AUTOMATED_SCANNER")
        risk_score += 35

    entropy = calculate_shannon_entropy(query + body)
    if entropy > 4.6 and len(query + body) > 20:
        detected_threats.append("HIGH_ENTROPY_OBFUSCATION")
        risk_score += 30

    risk_score = min(risk_score, 100)
    severity = "CRITICAL" if risk_score >= 80 else "HIGH" if risk_score >= 45 else "MEDIUM" if risk_score >= 25 else "SAFE"

    return {
        "is_malicious": risk_score >= 30,
        "risk_score": risk_score,
        "severity": severity,
        "threats": list(set(detected_threats)) if detected_threats else ["CLEAN_TRAFFIC"],
        "entropy": entropy,
        "payload_sample": full_payload[:120]
    }
