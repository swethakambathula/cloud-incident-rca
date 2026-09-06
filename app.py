"""
Entrypoint for Cloud Incident RCA Agent web dashboard.
Delegates to app.main.
"""
from app.main import app

if __name__ == "__main__":
    import os
    import uvicorn
    port = int(os.getenv("PORT", "8080"))
    uvicorn.run("app.main:app", host="0.0.0.0", port=port)
