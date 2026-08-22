from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

app = FastAPI()

# VULNERABLE ENDPOINT
@app.get("/")
async def root(request: Request):
    # Simulate a SQL injection leak
    query = request.query_params.get("id", "1")
    if "OR '1'='1'" in query:
        return HTMLResponse(content="EXPLOIT_LEAK: admin_password=supersecret", status_code=200)
    return HTMLResponse(content="Hello World")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
