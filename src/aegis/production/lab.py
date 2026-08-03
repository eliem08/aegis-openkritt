"""Benign local target used only by the opt-in Compose lab profile."""

from fastapi import FastAPI

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/healthz")
def healthz():
    return {"status": "ok", "target": "authorized-local-lab"}


@app.get("/headers")
def headers():
    return {"lab": True}


def main() -> None:
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8081, server_header=False)


if __name__ == "__main__":
    main()
