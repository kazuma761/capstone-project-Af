import os
from groq import Groq

class SecurityChatbot:
    def __init__(self):
        self.client = Groq(api_key=os.getenv("GROQ_API_KEY"))
        self.model = "llama-3.3-70b-versatile"
        
        self.system_prompt = """You are a professional cybersecurity assistant for a threat detection system. 

Your role:
- Explain scan results and security threats clearly
- Provide actionable security advice
- Answer questions about file safety and malware
- Guide users on best practices

Keep responses:
- Professional and concise
- Technically accurate
- User-friendly
- Under 150 words

Do not:
- Provide medical, legal, or financial advice
- Discuss topics unrelated to cybersecurity
- Make guarantees about absolute security"""

    async def chat(self, user_message: str, conversation_history: list = None) -> str:
        """
        Send a message to the chatbot and get a response
        
        Args:
            user_message: The user's question
            conversation_history: Optional list of previous messages
            
        Returns:
            The chatbot's response
        """
        try:
            messages = [{"role": "system", "content": self.system_prompt}]
            
            # Add conversation history if provided
            if conversation_history:
                messages.extend(conversation_history)
            
            # Add current user message
            messages.append({"role": "user", "content": user_message})
            
            # Get response from Groq
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0.7,
                max_tokens=300,
                top_p=1,
                stream=False
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            print(f"Chatbot error: {e}")
            return "I apologize, but I'm having trouble processing your request. Please try again or contact support if the issue persists."

# Global instance
chatbot = SecurityChatbot()
