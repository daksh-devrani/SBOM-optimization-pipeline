"""
LLM client configuration.
Supports Groq (CI/production) and Ollama (local dev) via env var switch.

Usage:
    from config.llm import get_llm
    llm = get_llm()
"""

import os
from langchain_groq import ChatGroq
from langchain_ollama import ChatOllama


def get_llm():
    """
    Returns the appropriate LLM client based on environment.

    Set LLM_PROVIDER=ollama for local development.
    Defaults to Groq (used in CI).
    """
    provider = os.getenv("LLM_PROVIDER", "groq").lower()

    if provider == "ollama":
        return ChatOllama(
            model=os.getenv("OLLAMA_MODEL", "llama3"),
            temperature=0,
        )

    # Default: Groq
    return ChatGroq(
        model=os.getenv("GROQ_MODEL", "llama3-70b-8192"),
        api_key=os.getenv("GROQ_API_KEY"),
        temperature=0,       # Deterministic output — critical for security tooling
        max_tokens=4096,
    )