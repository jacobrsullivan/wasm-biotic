# OpenRouter KISS Operator Note

This repository now supports an opt-in `openrouter_chat_completions` inference provider mode.

Operational constraints:

- Keep OpenRouter provider registration explicit and manual. Do not replace the seeded `open_ai_responses` provider path or `Factory_01` defaults.
- Set `api_base_url` to `https://openrouter.ai/api/v1` and `api_key_env_var` to an operator-managed secret such as `OPENROUTER_API_KEY`.
- Choose an explicit `model_ref`. The runtime accepts OpenRouter model ids directly, including `openrouter/free`.
- The authoritative output contract remains the existing Wasm-Biotic JSON turn contract. Native provider `tool_calls` are not executed directly in this mode.
- `response_schema_json` is still rendered into the turn package contract, but v1 does not translate it into provider-native schema enforcement for OpenRouter.

Registration example: [`artifacts/openrouter/provider-openrouter-example.json`](../artifacts/openrouter/provider-openrouter-example.json)
