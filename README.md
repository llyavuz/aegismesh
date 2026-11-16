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

1. Depoyu klonlayın ve klasöre girin:
   git clone https://github.com/KULLANICI_ADIN/aegismesh.git
   cd aegismesh

2. Sanal ortam oluşturun ve aktif edin:
   python -m venv .venv
   .venv\Scripts\activate

3. Bağımlılıkları yükleyin:
   pip install -r requirements.txt

4. Sunucuyu başlatın:
   uvicorn main:app --reload

Tarayıcınızdan `http://127.0.0.1:8000` adresine giderek **AI-SOC Komuta Merkezi**'ne erişebilir, **"Red Team Saldırı Simülasyonu Başlat"** veya **"Honeypot Tuzağını Tetikle"** butonlarıyla sistemi canlı test edebilirsiniz.

---

## Geliştirme Metodolojisi & Şeffaflık Beyanı

> **AI-Assisted Engineering:** Bu proje; siber savunma mimarisi (Honeypot/Tarpit, Shannon Entropy anomali tespiti, Auto-WAF kural üretimi), asenkron backend/WebSocket altyapısı ve gerçek zamanlı SOC arayüzü tasarımında **yapay zeka ile eşli programlama (AI Pair Programming)** yaklaşımıyla geliştirilmiştir. Tüm bileşenler yerel ortamda uçtan uca test edilip doğrulanmıştır.
