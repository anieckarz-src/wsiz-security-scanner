import socket
from typing import Dict, List
from urllib.parse import urlparse
from config import COMMON_PORTS, REQUEST_TIMEOUT


class PortScanner:
    
    def __init__(self, url: str):
        self.url = url
        self.hostname = urlparse(url).netloc or urlparse(url).path
        self.findings = []
        
    def analyze(self) -> Dict:
        print(f"[*] Skanuję porty dla {self.hostname}")
        
        try:
            open_ports = self._scan_ports(COMMON_PORTS)
            
            self._analyze_ports(open_ports)
            
            return {
                'module': 'Port Scanning',
                'status': 'completed',
                'open_ports': open_ports,
                'findings': self.findings
            }
            
        except Exception as e:
            return {
                'module': 'Port Scanning',
                'status': 'error',
                'error': str(e),
                'findings': [{'severity': 'MEDIUM', 'message': f'Błąd skanowania portów: {str(e)}'}]
            }
    
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
                print(f"  [+] Port {port} otwarty ({service})")
        
        return open_ports
    
    def _check_port(self, port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((self.hostname, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _identify_service(self, port: int) -> str:
        common_services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt',
            27017: 'MongoDB'
        }
        
        return common_services.get(port, f'Unknown (port {port})')
    
    def _analyze_ports(self, open_ports: List[Dict]):
        if not open_ports:
            self.findings.append({
                'severity': 'INFO',
                'category': 'Port Scanning',
                'message': 'Nie wykryto otwartych portów z listy standardowych portów',
                'note': 'To może oznaczać dobrą konfigurację firewall lub że usługi działają na niestandardowych portach'
            })
            return
        
        web_ports = [p for p in open_ports if p['port'] in [80, 443, 8080, 8443]]
        if web_ports:
            self.findings.append({
                'severity': 'PASS',
                'category': 'Port Scanning',
                'message': f'Wykryto standardowe porty web: {", ".join([str(p["port"]) for p in web_ports])}',
                'ports': [p['port'] for p in web_ports]
            })
        
        http_port = next((p for p in open_ports if p['port'] == 80), None)
        if http_port:
            self.findings.append({
                'severity': 'MEDIUM',
                'category': 'Port Scanning',
                'message': 'Port 80 (HTTP) jest otwarty',
                'recommendation': 'Upewnij się, że ruch HTTP jest przekierowywany na HTTPS',
                'port': 80
            })

        dangerous_ports = {
            21: ('FTP', 'HIGH', 'FTP przesyła dane w tekście jawnym'),
            23: ('Telnet', 'CRITICAL', 'Telnet jest niezabezpieczony, użyj SSH'),
            3306: ('MySQL', 'HIGH', 'Baza danych nie powinna być dostępna publicznie'),
            5432: ('PostgreSQL', 'HIGH', 'Baza danych nie powinna być dostępna publicznie'),
            27017: ('MongoDB', 'HIGH', 'Baza danych nie powinna być dostępna publicznie'),
            3389: ('RDP', 'HIGH', 'RDP nie powinien być dostępny publicznie'),
            5900: ('VNC', 'HIGH', 'VNC nie powinien być dostępny publicznie')
        }
        
        for port_info in open_ports:
            port = port_info['port']
            if port in dangerous_ports:
                service, severity, message = dangerous_ports[port]
                self.findings.append({
                    'severity': severity,
                    'category': 'Port Scanning',
                    'message': f'Wykryto potencjalnie niebezpieczny port {port} ({service})',
                    'details': message,
                    'recommendation': f'Ogranicz dostęp do portu {port} lub całkowicie go wyłącz',
                    'port': port
                })
        
        self.findings.append({
            'severity': 'INFO',
            'category': 'Port Scanning',
            'message': f'Znaleziono {len(open_ports)} otwartych portów',
            'ports': [f"{p['port']} ({p['service']})" for p in open_ports]
        })

