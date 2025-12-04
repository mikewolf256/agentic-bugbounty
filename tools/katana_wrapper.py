from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import subprocess

app = FastAPI(title="Katana Wrapper")

class KatanaRequest(BaseModel):
    target: str
    depth: int = 3
    crawl_scope: str = "host"

class KatanaResponse(BaseModel):
    target: str
    depth: int
    crawl_scope: str
    urls: list[str]
    raw: str | None = None

@app.post("/run_katana", response_model=KatanaResponse)
def run_katana(req: KatanaRequest):
    cmd = [
        "katana",
        "-u", req.target,            # explicit input URL
        "-system-scope",             # allow crawling that target
        "-jsonl",
        "-silent",
        "-depth", str(req.depth),
        "-crawl-scope", req.crawl_scope,
        "-automatic-form-fill",
        "-automatic-collect",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error running katana: {e}")

    if proc.returncode != 0:
        raise HTTPException(
            status_code=500,
            detail=f"Katana failed (exit {proc.returncode}): {proc.stderr or proc.stdout}",
        )

    urls: list[str] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        urls.append(line)

    return KatanaResponse(
        target=req.target,
        depth=req.depth,
        crawl_scope=req.crawl_scope,
        urls=urls,
        raw=None,
    )