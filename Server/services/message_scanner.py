import re
import os
from groq import Groq
from typing import Dict, Any, List

class MessageScanner:
    """Scam/Phishing message detection service using AI and rule-based analysis"""
    
    # Common scam indicators and their weights
    SCAM_INDICATORS = {
        # Urgency patterns
        "urgent": 15,
        "immediately": 15,
        "act now": 20,
        "limited time": 15,
        "expires": 10,
        "deadline": 10,
        "hurry": 12,
        "don't delay": 15,
        "time sensitive": 15,
        "last chance": 18,
        
        # Financial/Prize patterns
        "won": 20,
        "winner": 20,
        "lottery": 25,
        "prize": 18,
        "free money": 25,
        "cash prize": 25,
        "inheritance": 22,
        "million dollars": 25,
        "bitcoin": 15,
        "crypto": 12,
        
        # Account/Security threats
        "account suspended": 25,
        "verify your account": 20,
        "confirm your identity": 18,
        "unusual activity": 18,
        "security alert": 15,
        "password expired": 20,
        "unauthorized access": 18,
        "account locked": 22,
        "suspended": 15,
        
        # Payment/Financial requests
        "wire transfer": 25,
        "gift card": 25,
        "western union": 25,
        "moneygram": 25,
        "bank details": 20,
        "credit card": 15,
        "social security": 25,
        "ssn": 25,
        "tax refund": 22,
        
        # Impersonation indicators
        "irs": 20,
        "government": 15,
        "fbi": 22,
        "microsoft support": 25,
        "apple support": 25,
        "tech support": 20,
        "customer service": 12,
        
        # Suspicious links/actions
        "click here": 15,
        "click the link": 18,
        "download": 12,
        "attachment": 10,
        "verify now": 18,
        "update now": 15,
        "confirm now": 18,
        
        # Grammar/Style patterns (often in scams)
        "dear customer": 10,
        "dear user": 10,
        "dear friend": 12,
        "congratulations": 15,
        "you have been selected": 20,
        "you are a winner": 25,
        
        # Threat indicators
        "legal action": 20,
        "arrest warrant": 25,
        "police": 15,
        "lawsuit": 18,
        "court": 15,
    }
    
    # Legitimate patterns that reduce scam score
    LEGITIMATE_INDICATORS = {
        "unsubscribe": -10,
        "privacy policy": -8,
        "terms of service": -8,
        "official": -5,
        "receipt": -8,
        "order confirmation": -10,
        "tracking number": -12,
    }
    
    def __init__(self):
        self.client = Groq(api_key=os.getenv("GROQ_API_KEY")) if os.getenv("GROQ_API_KEY") else None
        self.model = "llama-3.3-70b-versatile"
    
    async def analyze_message(self, message: str) -> Dict[str, Any]:
        """
        Analyze a message for scam/phishing indicators
        
        Args:
            message: The message text to analyze
            
        Returns:
            Analysis result with risk score and breakdown
        """
        message_lower = message.lower()
        
        # Rule-based analysis
        rule_analysis = self._rule_based_analysis(message_lower)
        
        # AI analysis (if available)
        ai_analysis = await self._ai_analysis(message) if self.client else None
        
        # Combine analyses
        combined_score = rule_analysis["risk_score"]
        if ai_analysis and ai_analysis.get("risk_score"):
            # Weight: 60% rule-based, 40% AI
            combined_score = int(rule_analysis["risk_score"] * 0.6 + ai_analysis["risk_score"] * 0.4)
        
        # Determine verdict
        if combined_score >= 70:
            verdict = "scam"
            threat_level = "high"
        elif combined_score >= 40:
            verdict = "suspicious"
            threat_level = "medium"
        elif combined_score >= 20:
            verdict = "potentially_suspicious"
            threat_level = "low"
        else:
            verdict = "likely_safe"
            threat_level = "clean"
        
        return {
            "message_preview": message[:200] + "..." if len(message) > 200 else message,
            "verdict": verdict,
            "threat_level": threat_level,
            "risk_score": combined_score,
            "max_score": 100,
            "features_detected": rule_analysis["features_detected"],
            "feature_scores": rule_analysis["feature_scores"],
            "categories": rule_analysis["categories"],
            "ai_analysis": ai_analysis.get("analysis") if ai_analysis else None,
            "recommendations": self._get_recommendations(verdict),
            "scanner": "AI + Rule-based Message Scanner"
        }
    
    def _rule_based_analysis(self, message_lower: str) -> Dict[str, Any]:
        """Perform rule-based scam detection"""
        total_score = 0
        features_detected = []
        feature_scores = {}
        categories = {
            "urgency": 0,
            "financial": 0,
            "threats": 0,
            "impersonation": 0,
            "suspicious_links": 0,
            "personal_info_request": 0
        }
        
        # Check scam indicators
        for pattern, weight in self.SCAM_INDICATORS.items():
            if pattern in message_lower:
                total_score += weight
                features_detected.append(pattern)
                feature_scores[pattern] = weight
                
                # Categorize
                if pattern in ["urgent", "immediately", "act now", "limited time", "expires", "deadline", "hurry", "don't delay", "time sensitive", "last chance"]:
                    categories["urgency"] += weight
                elif pattern in ["won", "winner", "lottery", "prize", "free money", "cash prize", "inheritance", "million dollars", "bitcoin", "crypto", "wire transfer", "gift card", "western union", "moneygram", "tax refund"]:
                    categories["financial"] += weight
                elif pattern in ["legal action", "arrest warrant", "police", "lawsuit", "court", "account suspended", "account locked"]:
                    categories["threats"] += weight
                elif pattern in ["irs", "government", "fbi", "microsoft support", "apple support", "tech support"]:
                    categories["impersonation"] += weight
                elif pattern in ["click here", "click the link", "download", "attachment", "verify now", "update now", "confirm now"]:
                    categories["suspicious_links"] += weight
                elif pattern in ["bank details", "credit card", "social security", "ssn", "verify your account", "confirm your identity"]:
                    categories["personal_info_request"] += weight
        
        # Check legitimate indicators
        for pattern, weight in self.LEGITIMATE_INDICATORS.items():
            if pattern in message_lower:
                total_score += weight  # weight is negative
                features_detected.append(f"[legitimate] {pattern}")
                feature_scores[f"[legitimate] {pattern}"] = weight
        
        # Additional heuristics
        # Check for excessive caps
        caps_ratio = sum(1 for c in message_lower if c.isupper()) / max(len(message_lower), 1)
        if caps_ratio > 0.3:
            total_score += 10
            features_detected.append("excessive_caps")
            feature_scores["excessive_caps"] = 10
        
        # Check for suspicious URLs
        url_pattern = r'https?://[^\s]+'
        urls = re.findall(url_pattern, message_lower)
        if urls:
            for url in urls:
                if any(sus in url for sus in [".xyz", ".tk", ".ml", ".ga", ".cf", "bit.ly", "tinyurl"]):
                    total_score += 15
                    features_detected.append(f"suspicious_url: {url[:50]}")
                    feature_scores["suspicious_url"] = 15
                    categories["suspicious_links"] += 15
        
        # Check for phone numbers with specific patterns
        phone_pattern = r'\+?\d{1,3}[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'
        if re.search(phone_pattern, message_lower):
            total_score += 8
            features_detected.append("contains_phone_number")
            feature_scores["contains_phone_number"] = 8
        
        # Normalize score to 0-100
        total_score = min(max(total_score, 0), 100)
        
        return {
            "risk_score": total_score,
            "features_detected": features_detected,
            "feature_scores": feature_scores,
            "categories": categories
        }
    
    async def _ai_analysis(self, message: str) -> Dict[str, Any]:
        """Perform AI-based scam analysis"""
        try:
            prompt = f"""Analyze this message for scam/phishing indicators. Rate the risk from 0-100 and explain why.

Message:
{message[:1000]}

Respond in this exact format:
RISK_SCORE: [number 0-100]
ANALYSIS: [brief explanation in 2-3 sentences]
"""
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert analyzing messages for scam/phishing indicators. Be concise and accurate."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=200
            )
            
            content = response.choices[0].message.content
            
            # Parse response
            risk_score = 50  # default
            analysis = content
            
            if "RISK_SCORE:" in content:
                try:
                    score_line = content.split("RISK_SCORE:")[1].split("\n")[0].strip()
                    risk_score = int(re.search(r'\d+', score_line).group())
                except:
                    pass
            
            if "ANALYSIS:" in content:
                analysis = content.split("ANALYSIS:")[1].strip()
            
            return {
                "risk_score": min(max(risk_score, 0), 100),
                "analysis": analysis
            }
            
        except Exception as e:
            print(f"AI analysis error: {e}")
            return None
    
    def _get_recommendations(self, verdict: str) -> List[str]:
        """Get recommendations based on verdict"""
        if verdict == "scam":
            return [
                "Do NOT click any links in this message",
                "Do NOT reply or provide any personal information",
                "Block the sender immediately",
                "Report this message to relevant authorities",
                "Delete this message"
            ]
        elif verdict == "suspicious":
            return [
                "Be very cautious with this message",
                "Verify the sender through official channels",
                "Do not click links - visit websites directly",
                "Never share personal or financial information",
                "When in doubt, delete the message"
            ]
        elif verdict == "potentially_suspicious":
            return [
                "Exercise caution with this message",
                "Verify any claims through official sources",
                "Be wary of clicking links",
                "Do not share sensitive information"
            ]
        else:
            return [
                "This message appears safe",
                "Always remain vigilant",
                "Report if you notice anything suspicious later"
            ]

# Global instance
message_scanner = MessageScanner()
