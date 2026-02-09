"""
VirusTotal Integration Module
"""
import httpx
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

class VirusTotalClient:
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {
            "x-apikey": api_key,
            "Accept": "application/json"
        }
        
    async def get_file_report(self, file_hash: str) -> Dict:
        """
        Get file report from VirusTotal by hash (MD5, SHA1, or SHA256)
        """
        if not self.api_key:
            return {"error": "No API key provided"}
            
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    f"{self.BASE_URL}/files/{file_hash}",
                    headers=self.headers,
                    timeout=10.0
                )
                
                if response.status_code == 200:
                    data = response.json()
                    attributes = data.get("data", {}).get("attributes", {})
                    
                    return {
                        "found": True,
                        "malicious": attributes.get("last_analysis_stats", {}).get("malicious", 0),
                        "suspicious": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
                        "total_engines": sum(attributes.get("last_analysis_stats", {}).values()),
                        "scan_date": attributes.get("last_analysis_date"),
                        "permalink": data.get("data", {}).get("links", {}).get("self"),  # API link, UI link is usually in attributes
                        "gui_link": f"https://www.virustotal.com/gui/file/{file_hash}",
                        "tags": attributes.get("tags", []),
                        "results": self._format_results(attributes.get("last_analysis_results", {}))
                    }
                elif response.status_code == 404:
                    return {"found": False, "message": "File not found in VirusTotal"}
                elif response.status_code == 401:
                    return {"error": "Invalid API Key"}
                elif response.status_code == 429:
                    return {"error": "Rate limit exceeded"}
                else:
                    return {"error": f"VirusTotal API Error: {response.status_code}"}
                    
            except Exception as e:
                logger.error(f"VirusTotal lookup failed: {str(e)}")
                return {"error": f"Connection failed: {str(e)}"}
    
    def _format_results(self, raw_results: Dict) -> Dict:
        """Format the engine results to be more compact"""
        formatted = {}
        for engine, result in raw_results.items():
            if result.get("category") in ["malicious", "suspicious"]:
                formatted[engine] = {
                    "category": result.get("category"),
                    "result": result.get("result")
                }
        return formatted
