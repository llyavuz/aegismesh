# AegisMesh — Autonomous AI-SOC, Deception Honeypot & Auto-WAF Engine

**AegisMesh**, web uygulamaları ve API altyapıları için geliştirilmiş; gelen HTTP trafiğini gerçek zamanlı olarak **imza analizi** ve **Shannon Bilgi Entropisi (Information Entropy)** ile denetleyen, saldırganları sahte tuzaklara (**Deception Honeypot & Tarpit**) çekerek oyalayan ve kritik tehditler için otomatik **Nginx/Cloudflare WAF** engelleme kuralları derleyen otonom bir Siber Savunma ve Operasyon Merkezi (SOC) motorudur.

---

## Temel Yetenekler ve Mimari

* **Shannon Entropy & Heuristic Tehdit Analizi (`core/analyzer.py`):** SQL Injection, XSS, Path Traversal, Command Injection imzalarının yanı sıra; WAF atlatmak için Base64/Hex ile gizlenmiş (obfuscated) yüksek entropili zararlı yükleri (`> 4.60 bits`) matematiksel olarak tespit eder.
* **Aktif Aldatma Teknolojisi (Deception Honeypot & Tarpit):** `/.env`, `/wp-login.php`, `/api/v1/debug/keys` gibi kritik hedefleri taklit eden sahte uç noktalarla saldırgan botları yakalar, Tarpit geciktirmesiyle zamanlarını tüketir ve sahte yem verilerle (Decoy Credentials) saldırgan davranışını kayıt altına alır.
* **Otonom WAF Kural Üretici (`core/waf_generator.py`):** Risk skoru `>= 75` olan saldırgan IP adreslerini otomatik karantinaya alır ve sistem yöneticisi için anında uygulanabilir Nginx engelleme kuralları üretir.
* **Gerçek Zamanlı SOC Komuta Merkezi:** HTML5 Canvas tabanlı kıtalararası saldırı vektör radarı, WebSocket canlı telemetri akışı ve XSS korumalı (DOM Safe Text Binding) karanlık mod operasyon arayüzü.

---

## Kurulum ve Çalıştırma

```bash
# 1. Depoyu klonlayın
git clone [https://github.com/KULLANICI_ADIN/aegismesh.git](https://github.com/KULLANICI_ADIN/aegismesh.git)
cd aegismesh

# 2. Sanal ortam oluşturun ve aktif edin
python -m venv .venv
.venv\Scripts\activate  # Windows

# 3. Bağımlılıkları yükleyin
pip install -r requirements.txt

# 4. Sunucuyu başlatın
uvicorn main:app --reload'
