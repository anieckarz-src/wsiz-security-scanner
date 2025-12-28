# Security Scanner

Prosty skaner bezpieczeństwa do testowania SSL/TLS i portów sieciowych.

## Wymagania

- Python 3.7+
- certifi (instalowane automatycznie)

## Instalacja

```bash
pip install -r requirements.txt
```

## Użycie

Domyślny cel (wsiz.edu.pl):
```bash
python security_scanner.py
```

Własny URL:
```bash
python security_scanner.py https://example.com
```

## Co skanuje

### 1. SSL/TLS i Certyfikat
- Ważność certyfikatu (data wygaśnięcia)
- Wydawca certyfikatu
- Wersje protokołów TLS (1.0, 1.1, 1.2, 1.3)
- Siła szyfrowania (bity)
- SAN (Subject Alternative Names)
- Weryfikacja certyfikatu

### 2. Skanowanie Portów
- Wykrywanie otwartych portów
- Identyfikacja usług (HTTP, HTTPS, FTP, SSH, MySQL, etc.)
- Analiza potencjalnie niebezpiecznych portów
- Standardowe porty web (80, 443, 8080, 8443)

## Przykładowe wyjście

```
======================================================================
  SECURITY SCANNER - Test Bezpieczeństwa Strony WWW
======================================================================

[*] Cel: https://wsiz.edu.pl
[*] Data: 2025-12-28 17:30:00

[1/2] ANALIZA SSL/TLS I CERTYFIKATU
----------------------------------------------------------------------
[*] Sprawdzam SSL/TLS dla wsiz.edu.pl
  [✓] Obsługiwane TLS 1.2
  [✓] Obsługiwane TLS 1.3 (najnowsza wersja)
  [✓] Certyfikat ważny (wygasa za 200 dni)
  [✓] Silne szyfrowanie: 256 bitów

[2/2] SKANOWANIE PORTÓW
----------------------------------------------------------------------
[*] Skanuję porty dla wsiz.edu.pl
  [+] Port 80 otwarty (HTTP)
  [+] Port 443 otwarty (HTTPS)
  [✓] Wykryto standardowe porty web: 80, 443
  [!] Port 80 (HTTP) jest otwarty
      → Upewnij się, że ruch HTTP jest przekierowywany na HTTPS
```

## Konfiguracja

Edytuj plik `config.py`:

```python
TARGET_URL = "https://wsiz.edu.pl"  # Domyślny URL
REQUEST_TIMEOUT = 10                 # Timeout w sekundach
COMMON_PORTS = [80, 443, ...]       # Porty do skanowania
```

## Struktura projektu

```
projekt/
├── security_scanner.py      # Główny skrypt
├── config.py               # Konfiguracja
├── requirements.txt        # Zależności
├── modules/
│   ├── ssl_tls_checker.py  # Moduł SSL/TLS
│   └── port_scanner.py     # Moduł skanowania portów
└── README.md
```

## Interpretacja wyników

- `[✓]` - Pozytywny wynik (OK)
- `[✗]` - Problem (CRITICAL/HIGH)
- `[!]` - Ostrzeżenie (MEDIUM)
- `[i]` - Informacja
- `[+]` - Wykryty otwarty port

## Uwagi

Projekt ma charakter edukacyjny. Wszystkie testy są pasywne i nieinwazyjne.
