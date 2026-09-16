import aiohttp
from config import get_settings

settings = get_settings()

class GoogleSafeBrowsing:
    def __init__(self):
        self.api_key = settings.google_safe_browsing_api_key
        self.base_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    async def check_url(self, url: str) -> dict:
        # Check if API key is configured
        if not self.api_key or self.api_key == "your-google-safe-browsing-api-key":
            return {
                "is_safe": None,
                "error": "Google Safe Browsing API key not configured",
                "message": "Please add GOOGLE_SAFE_BROWSING_API_KEY to .env file",
                "scanner": "Google Safe Browsing (not configured)"
            }
        
        payload = {
            "client": {
                "clientId": "cyber-detection-system",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}?key={self.api_key}",
                    json=payload
                ) as response:
                    response_text = await response.text()
                    print(f"Google Safe Browsing Response Status: {response.status}")
                    print(f"Google Safe Browsing Response: {response_text}")
                    
                    if response.status != 200:
                        return {
                            "is_safe": None,
                            "error": f"API Error: {response.status}",
                            "message": response_text,
                            "scanner": "Google Safe Browsing"
                        }
                    
                    data = await response.json()
                    
                    if "matches" in data and len(data["matches"]) > 0:
                        threats = [match["threatType"] for match in data["matches"]]
                        return {
                            "is_safe": False,
                            "threats": threats,
                            "details": data["matches"],
                            "scanner": "Google Safe Browsing"
                        }
                    else:
                        return {
                            "is_safe": True,
                            "threats": [],
                            "message": "No threats detected",
                            "scanner": "Google Safe Browsing",
                            "note": "API returned no matches"
                        }
        except Exception as e:
            print(f"Google Safe Browsing Error: {str(e)}")
            return {
                "is_safe": None,
                "error": str(e),
                "scanner": "Google Safe Browsing"
            }
