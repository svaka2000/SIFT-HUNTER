"""LLM factory — returns the best available chat model based on configured keys."""

from __future__ import annotations

from mcp_server.config import config


def get_llm(max_tokens: int = 2048):
    """Return a LangChain chat model using Groq if available, else Anthropic."""
    if config.GROQ_API_KEY:
        from langchain_groq import ChatGroq
        # Fallback model hierarchy: prefer 70b but fall back to 8b on rate limits
        groq_model = config.MODEL if "llama" in config.MODEL or "mixtral" in config.MODEL else "llama-3.1-8b-instant"
        return ChatGroq(
            model=groq_model,
            api_key=config.GROQ_API_KEY,
            max_tokens=max_tokens,
        )
    elif config.ANTHROPIC_API_KEY:
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(
            model=config.MODEL,
            api_key=config.ANTHROPIC_API_KEY,
            max_tokens=max_tokens,
        )
    else:
        raise RuntimeError(
            "No LLM API key configured. Set GROQ_API_KEY or ANTHROPIC_API_KEY."
        )
