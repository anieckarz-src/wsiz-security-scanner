import ssl
import socket
from datetime import datetime
from typing import Dict, List
from urllib.parse import urlparse
from config import REQUEST_TIMEOUT

try:
    import certifi
    CERTIFI_AVAILABLE = True
except ImportError:
    CERTIFI_AVAILABLE = False


class SSLTLSChecker:
    def __init__(self, url: str):
        self.url = url
        self.hostname = urlparse(url).netloc or urlparse(url).path
        self.findings = []
        
    def analyze(self) -> Dict:
        print(f"[*] Sprawdzam SSL/TLS dla {self.hostname}")
        
        try:
            cert_info = self._get_certificate_info()
            tls_versions = self._check_tls_versions()
            self._check_certificate(cert_info)
            cipher_info = self._check_ciphers()
            
            return {
                'module': 'SSL/TLS Analysis',
                'status': 'completed',
                'certificate': cert_info,
                'tls_versions': tls_versions,
                'cipher': cipher_info,
                'findings': self.findings
            }
            
        except Exception as e:
            return {
                'module': 'SSL/TLS Analysis',
                'status': 'error',
                'error': str(e),
                'findings': [{'severity': 'HIGH', 'message': f'Błąd analizy SSL/TLS: {str(e)}'}]
            }
    
    def _get_certificate_info(self) -> Dict:
        try:
            context = ssl.create_default_context()
            return self._fetch_cert_with_context(context, verify=True)
        except ssl.SSLError as e:
            if CERTIFI_AVAILABLE:
                try:
                    context = ssl.create_default_context(cafile=certifi.where())
                    return self._fetch_cert_with_context(context, verify=True)
                except Exception:
                    pass

            self.findings.append({
                'severity': 'MEDIUM',
                'category': 'Certificate Verification',
                'message': 'Nie można zweryfikować certyfikatu (problem z certyfikatami CA)',
                'details': f'Błąd: {str(e)}',
                'recommendation': 'Zainstaluj certifi: pip install certifi, lub zaktualizuj certyfikaty systemowe'
            })
            
            context = ssl._create_unverified_context()
            return self._fetch_cert_with_context(context, verify=False)
        except Exception as e:
            raise Exception(f"Nie można pobrać certyfikatu: {str(e)}")
    
    def _fetch_cert_with_context(self, context: ssl.SSLContext, verify: bool = True) -> Dict:
        with socket.create_connection((self.hostname, 443), timeout=REQUEST_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                
                result = {
                    'subject': dict(x[0] for x in cert.get('subject', [])),
                    'issuer': dict(x[0] for x in cert.get('issuer', [])),
                    'version': cert.get('version'),
                    'serial_number': cert.get('serialNumber'),
                    'not_before': cert.get('notBefore'),
                    'not_after': cert.get('notAfter'),
                    'san': self._extract_san(cert),
                    'cipher_suite': cipher[0] if cipher else None,
                    'tls_version': version,
                    'verified': verify
                }
                
                if not verify:
                    result['verification_warning'] = 'Certyfikat nie został zweryfikowany - możliwy problem z certyfikatami CA'
                
                return result
    
    def _extract_san(self, cert: Dict) -> List[str]:
        san = []
        if 'subjectAltName' in cert:
            for entry in cert['subjectAltName']:
                if entry[0] == 'DNS':
                    san.append(entry[1])
        return san
    
    def _check_certificate(self, cert_info: Dict):
        try:
            not_after = datetime.strptime(cert_info['not_after'], '%b %d %H:%M:%S %Y %Z')
            not_before = datetime.strptime(cert_info['not_before'], '%b %d %H:%M:%S %Y %Z')
            now = datetime.now()
            
            if now > not_after:
                self.findings.append({
                    'severity': 'CRITICAL',
                    'category': 'Certificate',
                    'message': 'Certyfikat wygasł!',
                    'details': f'Data wygaśnięcia: {cert_info["not_after"]}'
                })
            elif now < not_before:
                self.findings.append({
                    'severity': 'CRITICAL',
                    'category': 'Certificate',
                    'message': 'Certyfikat jeszcze nie jest ważny!',
                    'details': f'Data początku ważności: {cert_info["not_before"]}'
                })
            else:
                days_left = (not_after - now).days
                if days_left < 30:
                    severity = 'HIGH'
                    message = f'Certyfikat wygasa za {days_left} dni'
                elif days_left < 90:
                    severity = 'MEDIUM'
                    message = f'Certyfikat wygasa za {days_left} dni'
                else:
                    severity = 'PASS'
                    message = f'Certyfikat ważny (wygasa za {days_left} dni)'
                
                self.findings.append({
                    'severity': severity,
                    'category': 'Certificate',
                    'message': message,
                    'valid_from': cert_info['not_before'],
                    'valid_until': cert_info['not_after']
                })
        except Exception as e:
            self.findings.append({
                'severity': 'MEDIUM',
                'category': 'Certificate',
                'message': f'Nie można sprawdzić daty ważności: {str(e)}'
            })
        
        issuer = cert_info.get('issuer', {})
        if issuer:
            self.findings.append({
                'severity': 'INFO',
                'category': 'Certificate',
                'message': f'Wydawca certyfikatu: {issuer.get("organizationName", "Unknown")}',
                'issuer': issuer
            })
        
        san = cert_info.get('san', [])
        if self.hostname in san or f'www.{self.hostname}' in san or any(self.hostname.endswith(s.replace('*.', '')) for s in san if s.startswith('*.')):
            self.findings.append({
                'severity': 'PASS',
                'category': 'Certificate',
                'message': 'Hostname znajduje się w SAN certyfikatu',
                'san': san
            })
        else:
            self.findings.append({
                'severity': 'MEDIUM',
                'category': 'Certificate',
                'message': 'Hostname może nie pasować do SAN certyfikatu',
                'hostname': self.hostname,
                'san': san
            })
    
    def _check_tls_versions(self) -> List[str]:
        supported_versions = []
        
        tls_versions = [
            ('TLSv1.3', ssl.PROTOCOL_TLS),
            ('TLSv1.2', ssl.PROTOCOL_TLSv1_2),
            ('TLSv1.1', ssl.PROTOCOL_TLSv1_1),
            ('TLSv1.0', ssl.PROTOCOL_TLSv1),
        ]
        
        for version_name, protocol in tls_versions:
            try:
                context = ssl.SSLContext(protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((self.hostname, 443), timeout=REQUEST_TIMEOUT) as sock:
                    with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                        supported_versions.append(version_name)
            except:
                pass
        
        if 'TLSv1.0' in supported_versions or 'TLSv1.1' in supported_versions:
            self.findings.append({
                'severity': 'HIGH',
                'category': 'TLS Version',
                'message': 'Wykryto obsługę przestarzałych wersji TLS (1.0/1.1)',
                'supported_versions': supported_versions,
                'recommendation': 'Wyłącz TLS 1.0 i 1.1, pozostaw tylko TLS 1.2 i 1.3'
            })
        
        if 'TLSv1.2' in supported_versions:
            self.findings.append({
                'severity': 'PASS',
                'category': 'TLS Version',
                'message': 'Obsługiwane TLS 1.2',
            })
        
        if 'TLSv1.3' in supported_versions:
            self.findings.append({
                'severity': 'PASS',
                'category': 'TLS Version',
                'message': 'Obsługiwane TLS 1.3 (najnowsza wersja)',
            })
        
        if not supported_versions:
            self.findings.append({
                'severity': 'CRITICAL',
                'category': 'TLS Version',
                'message': 'Nie wykryto żadnych obsługiwanych wersji TLS'
            })
        
        return supported_versions
    
    def _check_ciphers(self) -> Dict:
        try:
            context = ssl.create_default_context()
            return self._fetch_cipher_info(context)
        except ssl.SSLError:
            try:
                context = ssl._create_unverified_context()
                return self._fetch_cipher_info(context)
            except Exception as e:
                self.findings.append({
                    'severity': 'MEDIUM',
                    'category': 'Cipher',
                    'message': f'Nie można sprawdzić szyfrów: {str(e)}'
                })
                return {}
    
    def _fetch_cipher_info(self, context: ssl.SSLContext) -> Dict:
        with socket.create_connection((self.hostname, 443), timeout=REQUEST_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                cipher = ssock.cipher()
                
                cipher_info = {
                    'name': cipher[0] if cipher else None,
                    'protocol': cipher[1] if cipher and len(cipher) > 1 else None,
                    'bits': cipher[2] if cipher and len(cipher) > 2 else None
                }
                
                if cipher_info['bits']:
                    if cipher_info['bits'] >= 256:
                        severity = 'PASS'
                        message = f'Silne szyfrowanie: {cipher_info["bits"]} bitów'
                    elif cipher_info['bits'] >= 128:
                        severity = 'INFO'
                        message = f'Średnie szyfrowanie: {cipher_info["bits"]} bitów'
                    else:
                        severity = 'HIGH'
                        message = f'Słabe szyfrowanie: {cipher_info["bits"]} bitów'
                    
                    self.findings.append({
                        'severity': severity,
                        'category': 'Cipher',
                        'message': message,
                        'cipher': cipher_info['name']
                    })
                
                return cipher_info

