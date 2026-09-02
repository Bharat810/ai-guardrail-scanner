import os, requests
from dotenv import load_dotenv

load_dotenv()
key = os.getenv("GEMINI_API_KEY", "").strip("\"' ")
url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent?key={key}"
payload = {"contents": [{"parts": [{"text": "Hello"}]}]}

r = requests.post(url, json=payload)
print(f"Status: {r.status_code}")
print(f"Response: {r.text}")