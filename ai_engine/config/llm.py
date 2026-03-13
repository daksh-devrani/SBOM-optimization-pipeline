import os
import httpx
from langchain_groq import ChatGroq
from langchain_ollama import ChatOllama


def get_llm():
    provider = os.getenv("LLM_PROVIDER", "groq").lower()

    if provider == "ollama":
        return ChatOllama(
            model=os.getenv("OLLAMA_MODEL", "llama3"),
            temperature=0,
        )

    api_key = os.getenv("GROQ_API_KEY")

    if not api_key:
        raise ValueError(
            "GROQ_API_KEY is not set. "
            "Add it to GitHub Actions secrets and pass via env: in your workflow step."
        )

    return ChatGroq(
        model=os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),  # ← updated
        api_key=api_key,
        temperature=0,
        max_tokens=4096,
        http_client=httpx.Client(timeout=60.0),
    )