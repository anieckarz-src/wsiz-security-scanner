#!/usr/bin/env python3

import sys
import io
from datetime import datetime
from typing import Dict, List
import traceback

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

from modules.ssl_tls_checker import SSLTLSChecker
from modules.port_scanner import PortScanner

from config import TARGET_URL


class SecurityScanner:
    def __init__(self, target_url: str = None):
        self.target_url = target_url or TARGET_URL
        self.results = {
            'scan_info': {
                'target': self.target_url,
                'timestamp': datetime.now().isoformat(),
                'scanner_version': '1.0.0'
            },
            'modules': []
        }
        
    def run(self):
        print("="*70)
        print("  SECURITY SCANNER - Test Bezpieczeństwa Strony WWW")
        print("="*70)
        print(f"\n[*] Cel: {self.target_url}")
        print(f"[*] Data: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("\n" + "="*70 + "\n")
        
        print("\n[1/2] ANALIZA SSL/TLS I CERTYFIKATU")
        print("-" * 70)
        try:
            ssl_checker = SSLTLSChecker(self.target_url)
            ssl_result = ssl_checker.analyze()
            self.results['modules'].append(ssl_result)
            self._print_module_summary(ssl_result)
        except Exception as e:
            print(f"[!] Błąd: {str(e)}")
            self.results['modules'].append({
                'module': 'SSL/TLS Analysis',
                'status': 'error',
                'error': str(e)
            })

        print("\n[2/2] SKANOWANIE PORTÓW")
        print("-" * 70)
        try:
            port_scanner = PortScanner(self.target_url)
            port_result = port_scanner.analyze()
            self.results['modules'].append(port_result)
            self._print_module_summary(port_result)
        except Exception as e:
            print(f"[!] Błąd: {str(e)}")
            self.results['modules'].append({
                'module': 'Port Scanning',
                'status': 'error',
                'error': str(e)
            })
        
    def _print_module_summary(self, result: Dict):
        if result['status'] == 'error':
            print(f"  [✗] BŁĄD: {result.get('error', 'Unknown error')}")
            return
        
        findings = result.get('findings', [])
        
        if findings:
            for finding in findings:
                sev = finding.get('severity', 'INFO')
                msg = finding.get('message', 'Brak opisu')

                if sev == 'PASS':
                    symbol = '[✓]'
                elif sev in ['CRITICAL', 'HIGH']:
                    symbol = '[✗]'
                elif sev == 'MEDIUM':
                    symbol = '[!]'
                else:
                    symbol = '[i]'
                
                print(f"  {symbol} {msg}")
            
                if 'details' in finding:
                    print(f"      Szczegóły: {finding['details']}")
                if 'recommendation' in finding:
                    print(f"      → {finding['recommendation']}")
        else:
            print(f"  [✓] Brak problemów")


def main():
    target_url = None
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    
    try:
        scanner = SecurityScanner(target_url)
        scanner.run()
        return 0
    except KeyboardInterrupt:
        print("\n\n[!] Skanowanie przerwane przez użytkownika")
        return 1
    except Exception as e:
        print(f"\n[!] Krytyczny błąd: {str(e)}")
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())

