import httpx

from app.core.config import settings


def generate(prompt: str, model: str | None = None) -> str:
    payload = {
        "model": model or settings.ollama_model,
        "prompt": prompt,
        "stream": False,
    }
    response = httpx.post(
        f"{settings.ollama_base_url}/api/generate", json=payload, timeout=60
    )
    response.raise_for_status()
    data = response.json()
    return data.get("response", "").strip()
