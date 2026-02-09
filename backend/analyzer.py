"""
Static Analysis Module

Performs static analysis on malware samples including:
- Hash calculation (MD5, SHA1, SHA256)
- File metadata extraction
- String extraction
- File type detection
- Entropy calculation
"""

import hashlib
import re
import math
from pathlib import Path
from typing import Dict, List, Optional
from collections import Counter


class StaticAnalyzer:
    """Static malware analysis engine"""
    
    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        self.file_content = None
        self.rules_path = Path.home() / ".malware-analyzer" / "rules"
        self._ensure_rules_dir()
        
    def _ensure_rules_dir(self):
        """Ensure rules directory exists and has default rules"""
        self.rules_path.mkdir(parents=True, exist_ok=True)
        default_rule = self.rules_path / "default.yar"
        if not default_rule.exists():
            # Copy from backend if available, or create minimal
            source = Path("backend/default_rules.yar")
            if source.exists():
                import shutil
                shutil.copy(source, default_rule)
        
    def analyze(self) -> Dict:
        """Run complete static analysis"""
        results = {}
        
        # Load file content
        try:
            with open(self.file_path, 'rb') as f:
                self.file_content = f.read()
        except Exception as e:
            return {"error": f"Failed to read file: {str(e)}"}
        
        # Perform analysis
        results['hashes'] = self.calculate_hashes()
        results['file_info'] = self.get_file_info()
        results['strings'] = self.extract_strings()
        results['entropy'] = self.calculate_entropy()
        results['entropy'] = self.calculate_entropy()
        results['file_type'] = self.detect_file_type()
        
        # Extended PE Analysis
        if results['file_type'].get('type') == 'PE':
            results['pe_info'] = self.analyze_pe()
            
        results['yara'] = self.scan_yara()
        
        return results

    def scan_yara(self) -> Dict:
        """Scan file with YARA rules (or fallback)"""
        try:
            import yara
            # Compile all .yar files in rules directory
            filepaths = {}
            for p in self.rules_path.glob("*.yar"):
                filepaths[str(p.name)] = str(p)
                
            if not filepaths:
                return {"matches": [], "info": "No YARA rules found"}
                
            rules = yara.compile(filepaths=filepaths)
            
            # Match rules
            yara_matches = rules.match(data=self.file_content)
            
            matches = []
            for match in yara_matches:
                matches.append({
                    "rule": match.rule,
                    "tags": match.tags,
                    "namespace": match.namespace,
                    "meta": match.meta
                })
                
            return {
                "matches": matches,
                "rules_count": len(filepaths)
            }
            
        except ImportError:
            print("WARNING: YARA library not found, using fallback scanner")
            return self._fallback_yara_scan()
        except Exception as e:
            return {"error": f"YARA scan failed: {str(e)}", "matches": []}

    def _fallback_yara_scan(self) -> Dict:
        """
        Simple pure-Python fallback for YARA scanning.
        Parses basic 'strings' sections from .yar files and checks for presence.
        """
        matches = []
        rule_count = 0
        
        try:
            # Iterate through all rule files
            for rule_file in self.rules_path.glob("*.yar"):
                rule_count += 1
                try:
                    content = rule_file.read_text(encoding='utf-8', errors='ignore')
                    
                    # Very basic parser for: rule Name { strings: ... }
                    # This is NOT a full YARA parser, just a helper for the standalone mode
                    import re
                    
                    # Find each rule block
                    rule_pattern = re.compile(r'rule\s+(\w+)\s*\{([^}]+)\}', re.MULTILINE | re.DOTALL)
                    
                    for rule_match in rule_pattern.finditer(content):
                        rule_name = rule_match.group(1)
                        rule_body = rule_match.group(2)
                        
                        # Extract strings section
                        strings_match = re.search(r'strings:\s*(.*?)(condition:|$)', rule_body, re.DOTALL)
                        if not strings_match:
                            continue
                            
                        strings_block = strings_match.group(1)
                        
                        # Extract individual strings defined as $s1 = "..."
                        # Supports: "string", nocase, wide, ascii
                        str_pattern = re.compile(r'\$\w+\s*=\s*"([^"]+)"\s*(.*)', re.MULTILINE)
                        
                        matched_strings = []
                        
                        for s_match in str_pattern.finditer(strings_block):
                            target_str = s_match.group(1)
                            modifiers = s_match.group(2).lower()
                            
                            is_match = False
                            
                            # Prepare file content for searching (bytes)
                            data = self.file_content
                            
                            # Handle wide (UTF-16LE)
                            if 'wide' in modifiers:
                                try:
                                    target_bytes = target_str.encode('utf-16le')
                                    if target_bytes in data:
                                        is_match = True
                                        # Simple case-insensitive check for wide
                                        if not is_match and 'nocase' in modifiers:
                                            # This is expensive for large files, doing lazy check
                                            # For exact "nocase" on wide in python:
                                            # We just skip complex wide+nocase in fallback for now unless exact match
                                            pass
                                except:
                                    pass
                                    
                            # Handle ascii (default)
                            if 'ascii' in modifiers or 'wide' not in modifiers:
                                target_bytes = target_str.encode('utf-8')
                                if 'nocase' in modifiers:
                                    if target_bytes.lower() in data.lower():
                                        is_match = True
                                else:
                                    if target_bytes in data:
                                        is_match = True
                                        
                            if is_match:
                                matched_strings.append(target_str)
                                
                        # If any string matched, we count it as a rule match (simplified condition)
                        # Real YARA evaluates "condition:", we assume "any of them" for fallback
                        if matched_strings:
                            matches.append({
                                "rule": rule_name,
                                "tags": ["fallback"],
                                "namespace": rule_file.name,
                                "meta": {"description": f"Matched strings: {', '.join(matched_strings[:3])}..."}
                            })
                            
                except Exception as e:
                    print(f"Error parsing rule {rule_file}: {e}")
                    
            return {
                "matches": matches,
                "rules_count": rule_count,
                "info": "Using fallback Python scanner (YARA lib missing)"
            }
            
        except Exception as e:
             return {"error": f"Fallback scan failed: {str(e)}", "matches": []}

    
    def calculate_hashes(self) -> Dict[str, str]:
        """Calculate file hashes"""
        hashes = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256()
        }
        
        for h in hashes.values():
            h.update(self.file_content)
        
        return {
            name: h.hexdigest() 
            for name, h in hashes.items()
        }
    
    def get_file_info(self) -> Dict:
        """Get basic file information"""
        return {
            'filename': self.file_path.name,
            'size_bytes': len(self.file_content),
            'size_kb': round(len(self.file_content) / 1024, 2),
            'size_mb': round(len(self.file_content) / (1024 * 1024), 2),
        }
    
    def extract_strings(self, min_length: int = 4, max_count: int = 100) -> Dict:
        """Extract ASCII and Unicode strings"""
        
        # ASCII strings (printable characters)
        ascii_pattern = rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}'
        ascii_strings = re.findall(ascii_pattern, self.file_content)
        ascii_strings = [s.decode('ascii', errors='ignore') for s in ascii_strings]
        
        # Unicode strings (little-endian UTF-16)
        unicode_pattern = rb'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + rb',}'
        unicode_strings = re.findall(unicode_pattern, self.file_content)
        unicode_strings = [s.decode('utf-16-le', errors='ignore') for s in unicode_strings]
        
        # Combine and filter
        all_strings = list(set(ascii_strings + unicode_strings))
        
        # Look for interesting strings
        interesting = self._find_interesting_strings(all_strings)
        
        return {
            'total_count': len(all_strings),
            'ascii_count': len(ascii_strings),
            'unicode_count': len(unicode_strings),
            'sample': all_strings[:max_count],  # First N strings
            'interesting': interesting
        }
    
    def _find_interesting_strings(self, strings: List[str]) -> Dict[str, List[str]]:
        """Find strings of interest (URLs, IPs, registry keys, etc.)"""
        interesting = {
            'urls': [],
            'ips': [],
            'emails': [],
            'registry_keys': [],
            'file_paths': [],
            'crypto': []
        }
        
        # Patterns
        url_pattern = re.compile(r'https?://[^\s]+', re.IGNORECASE)
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        registry_pattern = re.compile(r'HKEY_[A-Z_]+\\[^\s]+', re.IGNORECASE)
        path_pattern = re.compile(r'[A-Za-z]:\\[^\s]+', re.IGNORECASE)
        crypto_keywords = ['AES', 'RSA', 'SHA', 'MD5', 'encrypt', 'decrypt', 'cipher', 'key']
        
        for s in strings:
            # URLs
            if url_pattern.search(s):
                interesting['urls'].append(s)
            
            # IP addresses
            if ip_pattern.search(s):
                ips = ip_pattern.findall(s)
                interesting['ips'].extend(ips)
            
            # Emails
            if email_pattern.search(s):
                emails = email_pattern.findall(s)
                interesting['emails'].extend(emails)
            
            # Registry keys
            if registry_pattern.search(s):
                interesting['registry_keys'].append(s)
            
            # File paths
            if path_pattern.search(s):
                interesting['file_paths'].append(s)
            
            # Crypto-related
            if any(keyword.lower() in s.lower() for keyword in crypto_keywords):
                interesting['crypto'].append(s)
        
        # Remove duplicates and limit
        for key in interesting:
            interesting[key] = list(set(interesting[key]))[:20]  # Max 20 each
        
        return interesting
    
    def calculate_entropy(self) -> Dict:
        """Calculate file entropy (0-8, higher = more random/encrypted)"""
        if not self.file_content:
            return {'entropy': 0, 'verdict': 'unknown'}
        
        # Count byte frequencies
        byte_counts = Counter(self.file_content)
        file_size = len(self.file_content)
        
        # Calculate Shannon entropy
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / file_size
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        # Interpret entropy
        if entropy > 7.5:
            verdict = "Very High - Likely encrypted/packed"
        elif entropy > 7.0:
            verdict = "High - Possibly encrypted/compressed"
        elif entropy > 6.0:
            verdict = "Medium-High - Mixed content"
        elif entropy > 4.0:
            verdict = "Medium - Normal executable"
        else:
            verdict = "Low - Plain text or sparse data"
        
        return {
            'entropy': round(entropy, 3),
            'max': 8.0,
            'verdict': verdict
        }
    
    def detect_file_type(self) -> Dict:
        """Detect file type from magic bytes"""
        if len(self.file_content) < 4:
            return {'type': 'unknown', 'description': 'File too small'}
        
        # Magic byte signatures
        magic_bytes = self.file_content[:4]
        
        signatures = {
            b'MZ': {'type': 'PE', 'description': 'Windows Executable (PE/EXE/DLL)'},
            b'\x7fELF': {'type': 'ELF', 'description': 'Linux Executable (ELF)'},
            b'PK\x03\x04': {'type': 'ZIP', 'description': 'ZIP Archive'},
            b'Rar!': {'type': 'RAR', 'description': 'RAR Archive'},
            b'%PDF': {'type': 'PDF', 'description': 'PDF Document'},
            b'\xd0\xcf\x11\xe0': {'type': 'OLE', 'description': 'Microsoft Office Document (OLE)'},
        }
        
        # Check magic bytes
        for magic, file_info in signatures.items():
            if self.file_content.startswith(magic):
                return file_info
        
        # Check by extension as fallback
        ext = self.file_path.suffix.lower()
        extension_types = {
            '.exe': {'type': 'PE', 'description': 'Windows Executable'},
            '.dll': {'type': 'PE', 'description': 'Windows DLL'},
            '.sys': {'type': 'PE', 'description': 'Windows Driver'},
            '.bin': {'type': 'BIN', 'description': 'Binary File'},
        }
        
        return extension_types.get(ext, {'type': 'Unknown', 'description': 'Unknown file type'})
        
    def analyze_pe(self) -> Dict:
        """Analyze Windows PE/EXE/DLL files"""
        try:
            import pefile
        except ImportError:
            return {"error": "pefile library not installed"}
            
        try:
            pe = pefile.PE(data=self.file_content)
        except Exception as e:
            return {"error": f"Failed to parse PE: {str(e)}"}
            
        results = {
            'headers': {},
            'imports': {},
            'exports': [],
            'sections': [],
            'warnings': pe.get_warnings()
        }
        
        # Headers
        try:
            results['headers'] = {
                'machine': pe.FILE_HEADER.Machine,
                'timestamp': pe.FILE_HEADER.TimeDateStamp,
                'number_of_sections': pe.FILE_HEADER.NumberOfSections,
                'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                'image_base': hex(pe.OPTIONAL_HEADER.ImageBase),
                'subsystem': pe.OPTIONAL_HEADER.Subsystem,
            }
        except:
            pass
            
        # Imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', 'ignore')
                results['imports'][dll_name] = []
                for imp in entry.imports:
                    if imp.name:
                        results['imports'][dll_name].append(imp.name.decode('utf-8', 'ignore'))
                    else:
                        results['imports'][dll_name].append(f"ord:{imp.ordinal}")
                        
        # Exports
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    results['exports'].append(exp.name.decode('utf-8', 'ignore'))
                    
        # Sections
        for section in pe.sections:
            try:
                name = section.Name.decode('utf-8', 'ignore').strip('\x00')
                
                # Parse characteristics
                flags = []
                if section.Characteristics & 0x40000000:
                    flags.append("R")
                if section.Characteristics & 0x80000000:
                    flags.append("W")
                if section.Characteristics & 0x20000000:
                    flags.append("X")
                    
                results['sections'].append({
                    'name': name,
                    'virtual_address': hex(section.VirtualAddress),
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'entropy': section.get_entropy() if hasattr(section, 'get_entropy') else 0,
                    'flags': flags
                })
            except:
                pass
                
        return results


def calculate_threat_score(analysis_results: Dict) -> int:
    """
    Calculate threat score (0-100) based on analysis results
    Higher = more suspicious
    """
    score = 0
    
    # Entropy scoring (40 points max)
    entropy = analysis_results.get('entropy', {}).get('entropy', 0)
    if entropy > 7.5:
        score += 40  # Very high entropy = likely packed/encrypted
    elif entropy > 7.0:
        score += 30
    elif entropy > 6.5:
        score += 20
    
    # Interesting strings scoring (30 points max)
    interesting = analysis_results.get('strings', {}).get('interesting', {})
    if interesting.get('urls'):
        score += 10  # Contains URLs
    if interesting.get('ips'):
        score += 10  # Contains IP addresses
    if interesting.get('registry_keys'):
        score += 5   # Modifies registry
    if interesting.get('crypto'):
        score += 5   # Uses cryptography

    # YARA matches scoring (50 points max)
    yara_results = analysis_results.get('yara', {})
    yara_matches = yara_results.get('matches', [])
    if yara_matches:
        score += min(len(yara_matches) * 20, 50)  # 20 points per match, max 50
    
    # File type scoring (20 points max)
    file_type = analysis_results.get('file_type', {}).get('type', '')
    if file_type in ['PE', 'ELF']:
        score += 10  # Executable
        
    # PE Specific Scoring
    pe_info = analysis_results.get('pe_info', {})
    
    # Suspicious Imports
    suspicious_imports = {
        'LoadLibrary', 'GetProcAddress', 'VirtualAlloc', 'VirtualProtect',
        'WriteProcessMemory', 'CreateRemoteThread', 'InternetOpen', 
        'URLDownloadToFile', 'ShellExecute', 'RegOpenKey', 'CryptEncrypt'
    }
    
    found_suspicious = set()
    imports = pe_info.get('imports', {})
    for dll, funcs in imports.items():
        for func in funcs:
            for bad in suspicious_imports:
                if bad.lower() in func.lower():
                    found_suspicious.add(bad)
    
    if found_suspicious:
        score += min(len(found_suspicious) * 10, 40)  # Up to 40 points
        
    # Packed / High Entropy Sections
    sections = pe_info.get('sections', [])
    for section in sections:
        if section.get('entropy', 0) > 7.5:
            score += 15  # Specific packed section
            break
    
    # Small file size (10 points max) - very small executables are suspicious
    file_size = analysis_results.get('file_info', {}).get('size_kb', 0)
    if file_type in ['PE', 'ELF'] and file_size < 10:
        score += 10  # Very small executable
    
    # Cap at 100
    return min(score, 100)
