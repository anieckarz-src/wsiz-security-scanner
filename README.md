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

## Jak działa skaner

Skaner składa się z dwóch głównych modułów, które analizują bezpieczeństwo strony WWW:

### Architektura

```python
# security_scanner.py - główny punkt wejścia
class SecurityScanner:
    def __init__(self, target_url: str = None):
        self.target_url = target_url or TARGET_URL
        self.results = {
            'scan_info': {...},
            'modules': []
        }
    
    def run(self):
        # 1. Analiza SSL/TLS
        ssl_checker = SSLTLSChecker(self.target_url)
        ssl_result = ssl_checker.analyze()
        
        # 2. Skanowanie portów
        port_scanner = PortScanner(self.target_url)
        port_result = port_scanner.analyze()
```

### 1. Moduł SSL/TLS (`modules/ssl_tls_checker.py`)

Moduł analizuje certyfikaty SSL/TLS i protokoły szyfrowania.

#### Pobieranie informacji o certyfikacie

```python
def _get_certificate_info(self) -> Dict:
    # Tworzy bezpieczny kontekst SSL
    context = ssl.create_default_context()
    
    # Nawiązuje połączenie z serwerem na porcie 443
    with socket.create_connection((self.hostname, 443), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
            cert = ssock.getpeercert()  # Pobiera certyfikat
            cipher = ssock.cipher()     # Pobiera informacje o szyfrze
            version = ssock.version()   # Pobiera wersję TLS
            
            return {
                'subject': cert.get('subject'),
                'issuer': cert.get('issuer'),
                'not_after': cert.get('notAfter'),  # Data wygaśnięcia
                'san': self._extract_san(cert),      # Subject Alternative Names
                'cipher_suite': cipher[0],
                'tls_version': version
            }
```

#### Sprawdzanie ważności certyfikatu

```python
def _check_certificate(self, cert_info: Dict):
    not_after = datetime.strptime(cert_info['not_after'], '%b %d %H:%M:%S %Y %Z')
    now = datetime.now()
    
    if now > not_after:
        # Certyfikat wygasł - CRITICAL
        self.findings.append({
            'severity': 'CRITICAL',
            'message': 'Certyfikat wygasł!'
        })
    else:
        days_left = (not_after - now).days
        if days_left < 30:
            severity = 'HIGH'  # Wygasa za mniej niż 30 dni
        elif days_left < 90:
            severity = 'MEDIUM'
        else:
            severity = 'PASS'  # Wszystko OK
```

#### Testowanie wersji TLS

```python
def _check_tls_versions(self) -> List[str]:
    supported_versions = []
    
    # Testuje każdą wersję TLS osobno
    tls_versions = [
        ('TLSv1.3', ssl.PROTOCOL_TLS),
        ('TLSv1.2', ssl.PROTOCOL_TLSv1_2),
        ('TLSv1.1', ssl.PROTOCOL_TLSv1_1),
        ('TLSv1.0', ssl.PROTOCOL_TLSv1),
    ]
    
    for version_name, protocol in tls_versions:
        try:
            context = ssl.SSLContext(protocol)
            with socket.create_connection((self.hostname, 443)) as sock:
                with context.wrap_socket(sock) as ssock:
                    supported_versions.append(version_name)  # Wersja obsługiwana
        except:
            pass  # Wersja nieobsługiwana
    
    # Ostrzeżenie jeśli wykryto przestarzałe wersje
    if 'TLSv1.0' in supported_versions or 'TLSv1.1' in supported_versions:
        self.findings.append({
            'severity': 'HIGH',
            'message': 'Wykryto obsługę przestarzałych wersji TLS (1.0/1.1)'
        })
```

#### Analiza siły szyfrowania

```python
def _check_ciphers(self) -> Dict:
    context = ssl.create_default_context()
    with socket.create_connection((self.hostname, 443)) as sock:
        with context.wrap_socket(sock) as ssock:
            cipher = ssock.cipher()
            bits = cipher[2]  # Liczba bitów klucza
            
            if bits >= 256:
                severity = 'PASS'  # Silne szyfrowanie
            elif bits >= 128:
                severity = 'INFO'  # Średnie
            else:
                severity = 'HIGH'  # Słabe
```

### 2. Moduł skanowania portów (`modules/port_scanner.py`)

Moduł skanuje porty sieciowe w poszukiwaniu otwartych usług.

#### Skanowanie portów

```python
def _scan_ports(self, ports: List[int]) -> List[Dict]:
    open_ports = []
    
    for port in ports:
        if self._check_port(port):
            service = self._identify_service(port)
            open_ports.append({
                'port': port,
                'service': service,
                'protocol': 'TCP'
            })
    
    return open_ports
```

#### Sprawdzanie pojedynczego portu

```python
def _check_port(self, port: int) -> bool:
    try:
        # Tworzy gniazdo TCP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)  # Timeout 2 sekundy
        
        # Próbuje połączyć się z portem
        result = sock.connect_ex((self.hostname, port))
        sock.close()
        
        # result == 0 oznacza sukces (port otwarty)
        return result == 0
    except:
        return False  # Port zamknięty lub błąd
```

#### Identyfikacja usług

```python
def _identify_service(self, port: int) -> str:
    common_services = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        443: 'HTTPS',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        # ... więcej portów
    }
    
    return common_services.get(port, f'Unknown (port {port})')
```

#### Analiza bezpieczeństwa portów

```python
def _analyze_ports(self, open_ports: List[Dict]):
    # Sprawdza niebezpieczne porty
    dangerous_ports = {
        21: ('FTP', 'HIGH', 'FTP przesyła dane w tekście jawnym'),
        23: ('Telnet', 'CRITICAL', 'Telnet jest niezabezpieczony'),
        3306: ('MySQL', 'HIGH', 'Baza danych nie powinna być dostępna publicznie'),
        # ...
    }
    
    for port_info in open_ports:
        port = port_info['port']
        if port in dangerous_ports:
            service, severity, message = dangerous_ports[port]
            self.findings.append({
                'severity': severity,
                'message': f'Wykryto potencjalnie niebezpieczny port {port}',
                'recommendation': f'Ogranicz dostęp do portu {port}'
            })
    
    # Sprawdza port HTTP (powinien przekierowywać na HTTPS)
    if any(p['port'] == 80 for p in open_ports):
        self.findings.append({
            'severity': 'MEDIUM',
            'message': 'Port 80 (HTTP) jest otwarty',
            'recommendation': 'Upewnij się, że ruch HTTP jest przekierowywany na HTTPS'
        })
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
COMMON_PORTS = [80, 443, 8080, 8443, 21, 22, 25, 3306, 5432, 27017]  # Porty do skanowania
```

## Struktura projektu

```
projekt/
├── security_scanner.py      # Główny skrypt
├── config.py               # Konfiguracja
├── requirements.txt        # Zależności
├── modules/
│   ├── __init__.py
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
