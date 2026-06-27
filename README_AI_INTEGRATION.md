# AegisTrace AI Integration

This package adds an OpenRouter/OpenAI-compatible AI analysis layer to AegisTrace.

## What changed

- Uses OpenRouter-compatible endpoint by default:
  - Base URL: `https://openrouter.ai/api/v1`
  - Model: `openai/gpt-4o-mini`
- Keeps the existing local rule-based summary as fallback.
- Redacts sensitive fields before sending data to AI:
  - passwords
  - cookie values
  - tokens
  - sessions/secrets
- Adds high-risk download type findings for extensions such as `.exe`, `.zip`, `.rar`, `.ps1`, `.apk`, etc.
- Adds GUI fields for:
  - API key
  - model name
  - base URL

## Important security note

Do not commit `aegistrace_settings.json` if it contains real API keys.
Use `aegistrace_settings.example.json` as a template.

If an API key was already exposed, revoke/regenerate it from the provider dashboard.
