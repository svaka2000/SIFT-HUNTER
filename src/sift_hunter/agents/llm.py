"""LLM factory — returns Groq or Anthropic client based on available keys."""
from __future__ import annotations
import os


def get_llm(max_tokens: int = 2048, temperature: float = 0.1):
    """Return the best available LLM. Groq first (faster/cheaper), Anthropic fallback."""
    groq_key = os.environ.get("GROQ_API_KEY", "")
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")
    model = os.environ.get("SIFT_MODEL", "")

    if groq_key and not model.startswith("claude"):
        from langchain_groq import ChatGroq
        groq_model = model or "llama-3.1-8b-instant"
        return ChatGroq(api_key=groq_key, model=groq_model, max_tokens=max_tokens, temperature=temperature)

    if anthropic_key:
        from langchain_anthropic import ChatAnthropic
        anthropic_model = model or "claude-haiku-4-5-20251001"
        return ChatAnthropic(api_key=anthropic_key, model=anthropic_model,
                             max_tokens=max_tokens, temperature=temperature)

    raise RuntimeError(
        "No LLM API key found. Set GROQ_API_KEY or ANTHROPIC_API_KEY environment variable."
    )
