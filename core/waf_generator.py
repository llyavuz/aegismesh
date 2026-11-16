def generate_waf_rules(source_ip: str, threats: list[str], path: str) -> str:
    """Yakalanan saldırı vektörüne göre otomatik Nginx ve Cloudflare WAF kuralı üretir."""
    threat_label = threats[0] if threats else "ANOMALY"
    nginx_rule = f"# AegisMesh Auto-Mitigation ({threat_label})\ndeny {source_ip};"
    if "PATH_TRAVERSAL" in threats or "SENSITIVE_FILE_PROBE" in threats:
        nginx_rule += f"\nlocation ~* ({path.split('?')[0]}) {{ return 444; }}"
    return nginx_rule
