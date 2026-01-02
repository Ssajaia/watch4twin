#!/usr/bin/env python3
"""
watch4Twin - Evil Twin Detector (MVP)
Passive detection of suspicious access points using beacon frame analysis.
"""

import argparse
import sys
import time
from collections import defaultdict
from datetime import datetime
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
import json
import os

class EvilTwinDetector:
    def __init__(self, interface, scan_time, verbose=False):
        self.interface = interface
        self.scan_time = scan_time
        self.verbose = verbose
        self.networks = defaultdict(list)
        self.oui_cache = {}
        self.suspicious_count = 0
        
        # Common infrastructure vendor OUIs (these are typically legitimate)
        self.infrastructure_vendors = {
            'cisco', 'aruba', 'ruckus', 'meraki', 'ubiquiti', 
            'tp-link', 'netgear', 'd-link', 'mikrotik'
        }
        
        # Load OUI database if available
        self.load_oui_database()
    
    def load_oui_database(self):
        """Try to load OUI database from common locations"""
        oui_files = [
            '/usr/share/ieee-data/oui.txt',
            '/usr/local/etc/oui.txt',
            '/etc/oui.txt',
            'oui.txt'
        ]
        
        for oui_file in oui_files:
            if os.path.exists(oui_file):
                try:
                    with open(oui_file, 'r') as f:
                        for line in f:
                            if '(hex)' in line:
                                parts = line.split('(hex)')
                                if len(parts) == 2:
                                    oui = parts[0].strip().replace('-', ':').lower()
                                    vendor = parts[1].strip()
                                    self.oui_cache[oui] = vendor
                    if self.verbose:
                        print(f"[*] Loaded {len(self.oui_cache)} OUIs from {oui_file}")
                    break
                except Exception as e:
                    if self.verbose:
                        print(f"[-] Could not load OUI database: {e}")
    
    def get_vendor_from_mac(self, mac):
        """Extract vendor from MAC address (first 3 octets)"""
        oui_prefix = mac.lower().replace(':', '')[:6]
        
        # Check cache first
        for cached_oui in self.oui_cache:
            if cached_oui.replace(':', '').startswith(oui_prefix):
                return self.oui_cache[cached_oui]
        
        # If no OUI database, use simple prefix check
        common_ouis = {
            '00:50:f2': 'Cisco',
            '00:0c:29': 'VMware',
            '00:1a:11': 'Google',
            '00:26:bb': 'Apple',
            '00:22:72': 'Microsoft',
            '00:13:10': 'Aruba',
            '00:18:0a': 'Ruckus',
            '00:1b:2c': 'Ubiquiti'
        }
        
        mac_prefix = mac.lower()[:8]
        for prefix, vendor in common_ouis.items():
            if mac_prefix.startswith(prefix.lower()):
                return vendor
        
        return "Unknown"
    
    def is_infrastructure_vendor(self, vendor):
        """Check if vendor is typically an infrastructure provider"""
        vendor_lower = vendor.lower()
        for infra_vendor in self.infrastructure_vendors:
            if infra_vendor in vendor_lower:
                return True
        return False
    
    def parse_security(self, pkt):
        """Extract security information from beacon frame"""
        if not pkt.haslayer(Dot11Beacon):
            return "Open"
        
        # Check RSN (WPA2) and WPA information elements
        rsn_found = False
        wpa_found = False
        
        # Dot11Elt layers contain the information elements
        layer = pkt[Dot11Beacon].payload
        
        while layer:
            if hasattr(layer, 'ID'):
                # RSN Information Element (ID 48)
                if layer.ID == 48:
                    rsn_found = True
                # WPA Information Element (ID 221, vendor specific for WPA)
                elif layer.ID == 221:
                    if hasattr(layer, 'info'):
                        if b'\x00\x50\xf2\x01\x01\x00' in layer.info:
                            wpa_found = True
            
            if hasattr(layer, 'payload'):
                layer = layer.payload
            else:
                break
        
        # Determine security type
        cap = pkt[Dot11Beacon].cap
        if cap.privacy:
            if rsn_found:
                return "WPA2"
            elif wpa_found:
                return "WPA"
            else:
                return "WEP"
        
        return "Open"
    
    def parse_beacon(self, pkt):
        """Callback function to process each beacon frame"""
        if pkt.haslayer(Dot11Beacon):
            try:
                # Extract SSID
                ssid_elements = pkt[Dot11Elt]
                ssid = None
                
                # Find SSID element (ID 0)
                while ssid_elements:
                    if hasattr(ssid_elements, 'ID'):
                        if ssid_elements.ID == 0:
                            if ssid_elements.info:
                                ssid = ssid_elements.info.decode('utf-8', errors='ignore')
                            break
                    if hasattr(ssid_elements, 'payload'):
                        ssid_elements = ssid_elements.payload
                    else:
                        break
                
                if not ssid or ssid == "":
                    return
                
                # Extract BSSID
                bssid = pkt[Dot11].addr2
                if not bssid or bssid == "ff:ff:ff:ff:ff:ff":
                    return
                
                # Extract RSSI
                rssi = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else -100
                
                # Extract security type
                security = self.parse_security(pkt)
                
                # Extract vendor from MAC
                vendor = self.get_vendor_from_mac(bssid)
                
                # Check if we've already seen this BSSID for this SSID
                for existing_ap in self.networks[ssid]:
                    if existing_ap['bssid'] == bssid:
                        # Update RSSI if stronger signal
                        if rssi > existing_ap['rssi']:
                            existing_ap['rssi'] = rssi
                        return
                
                # Add new AP to network list
                ap_info = {
                    'bssid': bssid,
                    'rssi': rssi,
                    'security': security,
                    'vendor': vendor,
                    'timestamp': time.time()
                }
                
                self.networks[ssid].append(ap_info)
                
                if self.verbose:
                    print(f"[*] Detected: {ssid} - {bssid} ({vendor}) RSSI:{rssi}dBm Sec:{security}")
                    
            except Exception as e:
                if self.verbose:
                    print(f"[-] Error parsing packet: {e}")
    
    def analyze_network(self, ssid, aps):
        """Analyze a single network for evil twin indicators"""
        if len(aps) <= 1:
            return None
        
        results = {
            'ssid': ssid,
            'total_aps': len(aps),
            'legit_aps': [],
            'suspicious_aps': [],
            'flags': [],
            'verdict': 'Normal'
        }
        
        # Multiple BSSIDs 
        results['flags'].append('MULTIPLE_BSSIDS')
        
        # Check security mismatch
        security_types = set(ap['security'] for ap in aps)
        if len(security_types) > 1:
            results['flags'].append('SECURITY_MISMATCH')
        
        # Rule 3: Check signal strength outliers
        rssi_values = [ap['rssi'] for ap in aps]
        max_rssi = max(rssi_values)
        min_rssi = min(rssi_values)
        if max_rssi - min_rssi > 20:  # 20 dBm threshold
            results['flags'].append('RSSI_OUTLIER')
        
        # Rule 4: Check OUI mismatches
        vendors = [ap['vendor'] for ap in aps]
        infrastructure_vendors = []
        non_infrastructure_vendors = []
        
        for ap in aps:
            if self.is_infrastructure_vendor(ap['vendor']):
                infrastructure_vendors.append(ap)
            else:
                non_infrastructure_vendors.append(ap)
        
        if infrastructure_vendors and non_infrastructure_vendors:
            results['flags'].append('OUI_MISMATCH')
            results['legit_aps'] = infrastructure_vendors
            results['suspicious_aps'] = non_infrastructure_vendors
        else:
            results['legit_aps'] = aps
        
        # Determine verdict
        if len(results['flags']) >= 2:
            results['verdict'] = 'POTENTIAL_EVIL_TWIN'
            self.suspicious_count += 1
        
        return results
    
    def print_results(self, results):
        """Print analysis results in a clean format"""
        if not results:
            return
        
        print(f"\nSSID: {results['ssid']}")
        
        if results['verdict'] == 'Normal':
            print(f"  └─ Single AP detected — looks normal")
            return
        
        # Print legitimate APs
        for i, ap in enumerate(results['legit_aps']):
            prefix = "  ├─ Legit AP:" if i == 0 else "  │"
            print(f"{prefix} {ap['bssid']}  RSSI:{ap['rssi']:3}dBm  Security:{ap['security']:8}  Vendor:{ap['vendor']}")
        
        # Print suspicious APs
        for i, ap in enumerate(results['suspicious_aps']):
            prefix = "  ├─ Suspicious AP:" if i == 0 and results['legit_aps'] else "  ├─ AP:"
            print(f"{prefix} {ap['bssid']}  RSSI:{ap['rssi']:3}dBm  Security:{ap['security']:8}  Vendor:{ap['vendor']}")
        
        # Print flags
        if results['flags']:
            print(f"  ├─ Flags: {', '.join(results['flags'])}")
        
        # Print verdict
        verdict_symbol = "⚠️ " if results['verdict'] == 'POTENTIAL_EVIL_TWIN' else "ℹ️ "
        print(f"  └─ Verdict: {verdict_symbol} {results['verdict'].replace('_', ' ')}")
    
    def export_to_json(self, filename):
        """Export results to JSON file"""
        export_data = {
            'scan_timestamp': datetime.now().isoformat(),
            'interface': self.interface,
            'duration': self.scan_time,
            'total_networks': len(self.networks),
            'suspicious_networks': self.suspicious_count,
            'networks': {}
        }
        
        for ssid, aps in self.networks.items():
            export_data['networks'][ssid] = aps
        
        try:
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
            print(f"\n[+] Results exported to {filename}")
        except Exception as e:
            print(f"[-] Could not export to JSON: {e}")
    
    def run(self):
        """Main execution method"""
        print(f"[+] Evil Twin Detector — Passive Scan")
        print(f"[*] Interface: {self.interface}")
        print(f"[*] Scan duration: {self.scan_time}s")
        print(f"[*] Capturing beacon frames...\n")
        
        start_time = time.time()
        
        try:
            # Start sniffing
            sniff(iface=self.interface,
                  prn=self.parse_beacon,
                  timeout=self.scan_time,
                  store=0,
                  monitor=True)
        
        except PermissionError:
            print("[-] Permission denied. Please run with sudo.")
            sys.exit(1)
        except Exception as e:
            print(f"[-] Error during capture: {e}")
            sys.exit(1)
        
        # Analyze collected data
        print(f"\n{'='*60}")
        print(f"SCAN COMPLETE - Analyzing {len(self.networks)} networks...")
        print('='*60)
        
        all_results = []
        for ssid, aps in self.networks.items():
            result = self.analyze_network(ssid, aps)
            all_results.append(result)
        
        # Sort results: suspicious first, then by SSID
        all_results.sort(key=lambda x: (
            0 if x and x['verdict'] == 'POTENTIAL_EVIL_TWIN' else 1,
            x['ssid'] if x else ''
        ))
        
        # Print results
        for result in all_results:
            self.print_results(result)
        
        # Print summary
        print(f"\n{'='*60}")
        print(f"SUMMARY")
        print(f"  Total networks detected: {len(self.networks)}")
        print(f"  Networks with multiple APs: {len([r for r in all_results if r and r['total_aps'] > 1])}")
        print(f"  Potential evil twins: {self.suspicious_count}")
        print(f"  Scan duration: {time.time() - start_time:.1f}s")
        print(f"{'='*60}")
        
        return self.suspicious_count > 0

def main():
    parser = argparse.ArgumentParser(
        description="watch4Twin - Passive Evil Twin Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -i wlan0mon -t 30
  %(prog)s -i wlan0mon -t 60 -v
  %(prog)s -i wlan0mon -t 30 --export results.json
        
Note: Requires monitor mode interface and root privileges.
        """
    )
    
    parser.add_argument("-i", "--interface", 
                       required=True,
                       help="Monitor mode interface (e.g., wlan0mon)")
    
    parser.add_argument("-t", "--time", 
                       type=int, 
                       default=30,
                       help="Scan duration in seconds (default: 30)")
    
    parser.add_argument("-v", "--verbose", 
                       action="store_true",
                       help="Show all detected APs during scan")
    
    parser.add_argument("--export",
                       help="Export results to JSON file")
    
    args = parser.parse_args()
    
    
    if os.geteuid() != 0:
        print("[-] This script requires root privileges. Please run with sudo.")
        sys.exit(1)
    
    
    detector = EvilTwinDetector(
        interface=args.interface,
        scan_time=args.time,
        verbose=args.verbose
    )
    
    try:
        suspicious = detector.run()
        
        # Export if requested
        if args.export:
            detector.export_to_json(args.export)
        
        # Exit with appropriate code
        sys.exit(1 if suspicious else 0)
        
    except KeyboardInterrupt:
        print("\n\n[-] Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n[-] Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()