from test_api import full_check   # not: from detection import full_check

from fastapi import FastAPI
app = FastAPI()

@app.post("/v1/scan-prompt")
def scan_prompt(user_input: str):
    return full_check(user_input)