# Supervisor LLM Interface Runtime Adapter

1. `POST /api/llm-interface/providers` registers or replaces an external inference provider while keeping only Wasm-Biotic-owned config and env-var secret references.
2. `POST /api/llm-interface/turns` persists the opaque prompt/tool/schema payloads, executes a bounded OpenAI Responses turn, records attempts/usage/outcome artifacts, and exposes the result through `GET /api/llm-interface/turns` and `GET /api/llm-interface/turns/{id}`.
3. Provider registry entries and recorded turn evidence survive runtime restart because the durable truth lives under the LLM-interface artifact store.
4. Timeout and transport-degraded turns retry only within the declared generation policy, emit explicit degradation records, and remain replayable after reload.
5. Invalid inference requests stay operator-visible at the Wasm-Biotic boundary through `400` responses, while unresolved secret or transport failures surface as `500` execution failures rather than being silently collapsed.
