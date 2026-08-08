# OpenRouter — Design and Implementation Documentation

This document describes how OpenRouter is integrated into the **nanoclaw-workspace** project. It covers the framework choice, configuration, free-model strategy, routing modes, the harness that wraps free-model execution, the failure modes encountered in practice and the remediations that exist in code today, plus representative excerpts and tests.

The implementation lives almost entirely inside the agent container, in `nanoclaw/container/agent-runner/src/`. Anything mentioned without a project prefix is relative to that directory.

---

## 1. Framework / SDK choice

**No SDK is used.** OpenRouter is called via the native Node.js `fetch` API against its OpenAI-compatible HTTP endpoints:

- `GET  {baseUrl}/models`            — discover currently-listed free models
- `POST {baseUrl}/chat/completions`  — text-only and tool-calling inference

Rationale (inferred from architecture):

- The Anthropic SDK is reserved for the Claude Agent SDK execution path (the "paid" route). It cannot route to non-Claude models.
- OpenRouter is OpenAI-compatible, so a thin `fetch` wrapper avoids dragging in the OpenAI SDK as a second client surface.
- Free models behave inconsistently enough (see §6) that the call site needs full control over request shape, headers, error inspection, and response sanitization. An SDK abstraction would get in the way.

Primary call sites:

| File | Symbol | Purpose |
|------|--------|---------|
| `prompt-router.ts:250` | `fetchFreeCodingModels()` | Lists free coding models from `/models` |
| `prompt-router.ts:303` | `callModel()` | Stateless text-only completion |
| `prompt-router.ts:500` | `callModelWithTools()` | Tool-calling loop using OpenAI function-calling shape |
| `free-harness.ts:535` | `requestPlan()` | Planning call that precedes execution |
| `free-harness.ts:599` | `runLoopForModel()` | Per-model execution loop with scratchpad + tool dispatch |

---

## 2. Configuration

### Environment variables

Read primarily from `src/config.ts` (host-side, propagated into the container) and consumed by `container/agent-runner/src/prompt-router.ts`:

| Variable | Default | Notes |
|----------|---------|-------|
| `OPENROUTER_API_KEY` | — (required for free routes) | Bearer token in `Authorization` header |
| `OPENROUTER_BASE_URL` | `https://openrouter.ai/api/v1` | Override permitted for proxies/tests |
| `ROUTER_MODE` | `complex-paid` | One of `complex-paid` \| `simple-complex` \| `complex-free` |
| `ROUTER_SIMPLE_MODEL` | _(empty)_ | Force a specific OpenRouter model id, bypassing ranking |
| `NANOCLAW_FREE_HARNESS` | _(on)_ | Set to `off` to fall back to the legacy `tryFreeModelsWithTools` path |
| `NANOCLAW_FREE_HARNESS_COOLDOWN_HOURS` | `4` | Per-model cooldown after a recorded failure |
| `NANOCLAW_FREE_HARNESS_MAX_FAILURES` | `3` | Failures before a model is demoted from candidates |

### Secrets handling

Per `nanoclaw/CLAUDE.md`, API keys are managed by the **OneCLI gateway**. OneCLI injects credentials into containers at request time so the key is not baked into the image or passed as a long-lived env var. `prompt-router.ts:223 resolveOpenRouterProviderConfig()` is the single point that reads `OPENROUTER_API_KEY` from the process environment and throws if it is absent — making it the right place to instrument if the proxy ever changes hands.

### HTTP request shape

All requests use only two headers:

```
Content-Type: application/json
Authorization: Bearer ${OPENROUTER_API_KEY}
```

The optional OpenRouter attribution headers (`HTTP-Referer`, `X-Title`) are **not** sent in the current implementation. If/when the project wants public attribution on the OpenRouter dashboard, the place to add them is the two `fetch(...)` calls in `prompt-router.ts:311` and `prompt-router.ts:518`, plus the harness call at `free-harness.ts:641`.

---

## 3. Free-model strategy

The project deliberately uses **free OpenRouter models only** for its non-Claude routes. There is no paid-OpenRouter tier — paid routing always goes to the Anthropic SDK.

### Free model selection pipeline

`fetchFreeCodingModels()` at `prompt-router.ts:250` performs the discovery:

1. `GET /models`
2. Filter to `pricing.prompt === '0' && pricing.completion === '0'` (true free tier — not promotional credits).
3. Filter to ids matching coding-relevant name patterns (`prompt-router.ts:97 CODING_NAME_PATTERNS`):
   `coder`, `codestral`, `devstral`, `starcoder`, `deepseek`, `mimo`, `qwen`, `llama`, `gemma`, `phi`, `hermes`, `nemotron`.
4. Sort by `PREFERRED_CODING_MODELS` ranking (`prompt-router.ts:83`):
   - `google/gemma-4`
   - `qwen/qwen3-coder`
   - `mistralai/devstral`
   - `xiaomi/mimo`
   - `deepseek/deepseek-r1`
   - `deepseek/deepseek-v3`
   - `meta-llama/llama-3.3-70b`
   - `meta-llama/llama-4`
   - `nousresearch/hermes-3`
   - `nvidia/nemotron`

The list is intentionally **prefix-matched**, not exact-matched, so when OpenRouter renames or sub-versions a free slug (e.g. `meta-llama/llama-4-maverick:free`) the rank still applies.

### The universal safety net: `openrouter/free`

`resolveFreeModelCandidates()` (`prompt-router.ts:283`) appends the literal string `openrouter/free` at the bottom of the candidate list:

```ts
candidates.push(...rankedModels);
candidates.push('openrouter/free');
return uniqueModels(candidates);
```

This is OpenRouter's own routing alias that resolves to whatever free model is currently up. It is the model of last resort when every ranked candidate has hit a rate limit or returned a degenerate response, and it is also the only candidate that **survives** health-based demotion (`free-model-health.ts:58` — see §5.1).

### Override knob

If `ROUTER_SIMPLE_MODEL` is set, that id is unshifted to the front of the candidate list, before the ranked free models. Useful for pinning a specific model during testing without touching code.

---

## 4. Routing logic

### Three router modes

`selectExecutionPlan()` at `prompt-router.ts:203` is the dispatcher:

```ts
export function selectExecutionPlan(input: RouteSelectionInput): ExecutionPlan {
  if (input.routerMode === 'complex-free') {
    return { kind: 'sdk-free', reason: 'router mode complex-free' };
  }
  if (
    input.routerMode === 'simple-complex' &&
    input.hasOpenRouterKey &&
    !input.isScheduledTask
  ) {
    const decision = classifyPrompt(input.prompt);
    if (decision.tier === 'simple') {
      return { kind: 'simple-free', reason: decision.reason };
    }
    return { kind: 'sdk-default', reason: decision.reason };
  }
  return { kind: 'sdk-default', reason: 'default SDK path' };
}
```

| Mode | Behavior |
|------|----------|
| `complex-paid` (default) | All messages → Anthropic Claude Agent SDK. OpenRouter not used. |
| `simple-complex` | Classify the prompt; simple → OpenRouter free (text only), complex → Claude SDK. Scheduled tasks always use Claude SDK. |
| `complex-free` | All messages → OpenRouter free models, executed through the **free-harness** with bash + send_message + send_media tools. |

The **classifier** (`classifyPrompt()` at `prompt-router.ts:` ~115–200) inspects the user prompt for code blocks, file paths, agentic verbs (`edit`, `fix`, `deploy`, `migrate`, `commit`, `refactor`, …), technical terms (`function`, `api`, `docker`, `git`, …), ContentFunnel-domain terms (`pipeline`, `slug`, `intake`, `dispatch`, `zernio`, `beehiiv`, …), and multi-step markers (`first`, `then`, `next`, `finally`). Any hit ⇒ complex.

### Per-message override (`cc-paid`)

`nanoclaw/CLAUDE.md` documents the user-facing `cc-paid` command which writes a one-shot router override into the `router_state` kv table; `runAgent` consumes it atomically on the next turn. This is the **only** way a free-mode session escalates to paid Claude. Per the *user-controlled-routing* memory (and reinforced in `CLAUDE.md`): **no automatic escalation to paid models. Do not add router-side classifiers that silently flip modes.**

### Session compatibility

The Claude SDK supports `--continue` to resume a prior session, but only when the prior session was on the same provider. `SessionRecord` (`prompt-router.ts:7`) persists `routeMode`, `providerBaseUrl`, and `model` so the orchestrator can decide whether a new turn can attach to the previous session or must start fresh — important when alternating between paid and free in a single chat.

---

## 5. The free-harness (`complex-free` mode)

`complex-free` does not call `callModelWithTools()` directly — it runs through `container/agent-runner/src/free-harness.ts`, a KISS wrapper that adds the discipline free models lack on their own.

### 5.1 Architecture

For each user turn:

1. **Plan call** — `requestPlan()` (`free-harness.ts:535`) makes a small completion against the first candidate to produce a structured plan that lands in the per-group scratchpad (`groups/{folder}/.nanoclaw/free-scratchpad.md`).
2. **Pipeline state injection** — if the group's `CLAUDE.md` contains a `## ContentFunnel Operator` heading, current pipeline state is injected into the system prompt.
3. **Model ladder** — iterate over candidates from `resolveFreeModelCandidates()`, calling `runLoopForModel()` for each (`free-harness.ts:1078–1194`).
4. **Per-model loop** — up to 30 tool iterations with compaction every 8, JSON-first contract `{"final": "answer"}` (legacy `<final>...</final>` regex fallback at `extractFinal()`, `free-harness.ts:319`).
5. **H7 health logging** — every model outcome (`final | cap | stall | error | degenerate`) is appended to `groups/{folder}/.nanoclaw/free-model-health.jsonl` (`free-model-health.ts`).
6. **F1 fallback notice** — if execution falls off the first candidate onto the next, emit a single user-visible IPC status message via `emitIpcStatusMessage()` (`prompt-router.ts:360`).
7. **S1 stuck signal** — if the entire ladder is exhausted without a final answer, send a user-facing "I'm stuck" message rather than fail silently.

### 5.2 Per-model health (`free-model-health.ts`)

Models that repeatedly fail are demoted from the candidate list for a cooldown window:

- Cooldown: `NANOCLAW_FREE_HARNESS_COOLDOWN_HOURS` (default 4 h)
- Failure budget: `NANOCLAW_FREE_HARNESS_MAX_FAILURES` (default 3)
- **`openrouter/free` is exempted** and is always present as the safety net (`free-model-health.ts:58`).

This is a fire-and-forget JSONL append — never on the hot path, never blocks the turn.

---

## 6. Challenges and remediations

This is the section worth keeping current. Each entry pairs a real failure mode observed in practice with the code today that mitigates it.

### 6.1 Tool-call hallucination as plain text

**Symptom.** Free models that have seen Anthropic-style or DeepSeek-style training data sometimes emit XML tool invocations or JSON tool-call blocks **in the visible content** of a non-tool-calling response. Without filtering, that markup leaks to the user.

**Remediation.** `sanitizeToolCallLeakage()` at `prompt-router.ts:443`. Multi-pass regex strip:

```ts
export function sanitizeToolCallLeakage(text: string): string {
  let cleaned = text;

  // <tool_call>...</tool_call> blocks
  cleaned = cleaned.replace(/<tool_call>[\s\S]*?<\/tool_call>/g, '');
  cleaned = cleaned.replace(
    /<\|tool[▁_]?calls?\|>[\s\S]*?<\|\/tool[▁_]?calls?\|>/g,
    '',
  );

  // ```json {...name...arguments...} ``` fenced blocks
  cleaned = cleaned.replace(
    /```(?:json)?\s*\{[\s\S]*?"(?:name|tool|function)"[\s\S]*?"(?:arguments|parameters|input)"[\s\S]*?\}\s*```/g,
    '',
  );

  // Bare JSON tool-call objects naming our actual tools
  cleaned = cleaned.replace(
    /\{[\s\n]*"(?:name|tool)"[\s]*:[\s]*"(?:bash|send_message|send_media)"[^{}]*(?:\{[^{}]*\}[^{}]*)*\}/g,
    '',
  );

  // Anthropic-style <invoke>/<parameter> hallucinations
  cleaned = cleaned.replace(
    /[^\n]+\n\s*<\/parameter>[\s\S]*?(?:<\/(?:invoke|parameter|block|turn|turns|conversation)>[^\S\n]*\n?)+(?:\s*(?:None|null)\s*)?/g,
    '',
  );
  cleaned = cleaned.replace(
    /<\/?(?:invoke|parameter|block|turn|turns|conversation)[^>]*>/g,
    '',
  );

  cleaned = cleaned.replace(/\n{3,}/g, '\n\n').trim();
  return cleaned || '(I tried to process your request but couldn\'t produce a response. Please try again.)';
}
```

`CLAUDE.md`'s troubleshooting section makes this an explicit ongoing maintenance area: *"When new leak patterns appear, add regex patterns there, update the tests, then rebuild the container."*

### 6.2 Token-loop / degenerate output

**Symptom.** A free model "collapses" mid-stream and emits e.g. `oooooooo…` or a tiny repeating unit for thousands of tokens. (Originally observed on `nemotron-3-super-120b` per the comments in `free-harness.ts:826–829`.)

**Remediation.** `isDegenerate()` (`free-harness.ts:831`):

```ts
export function isDegenerate(text: string): boolean {
  const t = text.trim();
  if (!t) return false;
  // 50+ consecutive identical chars
  if (/(.)\1{49,}/s.test(t)) return true;
  // Short repeating unit (1-4 chars) repeated 25+ times
  if (/(.{1,4})\1{24,}/s.test(t)) return true;
  // Long response with tiny vocabulary
  if (t.length > 500) {
    const uniq = new Set(t).size;
    if (uniq < 15) return true;
  }
  return false;
}
```

A degenerate response is dropped, recorded as `degenerate` in the health log, and the ladder advances to the next candidate.

### 6.3 Placeholder echo

**Symptom.** The model returns the literal placeholder it was given (`...`, `your answer here`).

**Remediation.** `isPlaceholder()` (`free-harness.ts:815`) detects the pattern and triggers a one-time harness nudge asking for a real answer (`free-harness.ts:731`).

### 6.4 Stall (repeated identical tool calls)

**Symptom.** Model calls `bash: ls`, gets the same result, calls `bash: ls` again, ad infinitum.

**Remediation.** Hash `(tool_name, arguments, result)` per call; on the second identical hash nudge the model; on the (configurable, default 2) third escape to the next candidate. Implementation at `free-harness.ts:766–787`.

### 6.5 Silent long-running tasks

**Symptom.** Free models can grind through many `bash` calls without ever sending a status message to the user.

**Remediation.** **H6 progress nudge** at `free-harness.ts:790–804` — after 6 consecutive bash calls with no `send_message` or `send_media`, inject a one-time harness instruction telling the model to send a status update.

### 6.6 Rate limiting (HTTP 429)

**Symptom.** Free tier per-key/per-model quotas. Bursty failures clustered around new releases of high-traffic free models.

**Remediation.** Errors from `fetch` are not retried in place. They throw, the harness records `error`, and the model ladder advances. `prompt-router.test.ts:193` mocks a 429 and asserts fallback to `openrouter/free`. There is **no exponential-backoff retry** on the same model — the design prefers ladder-advance over backoff because it produces results faster and naturally load-balances against OpenRouter's own free-model availability.

### 6.7 Daily / monthly free-tier limits

**Symptom.** OpenRouter caps total free-tier usage per account regardless of model.

**Remediation.** Not handled specially — surfaces as a 429/403 at the request site and falls through the ladder. Exhaustion is reported to the user via the **S1 stuck signal**. Operationally the user can issue `cc-paid` to escalate the next turn to Claude.

### 6.8 Models ignoring `response_format: json_object`

**Symptom.** Several free models do not honor `response_format`, so the contract `{"final": "..."}` cannot be relied on.

**Remediation.** `extractFinal()` (`free-harness.ts:319`) tries JSON first, then falls back to a legacy `<final>...</final>` regex. The system prompt teaches both formats so the cheaper-to-parse JSON wins when available.

### 6.9 Streaming

Not used. All requests are synchronous `fetch` + `await response.json()`. The container's heartbeat marker (`emitToolHeartbeat()`, `prompt-router.ts:494`) keeps the host from killing the container during long tool turns; per-call streaming is unnecessary.

### 6.10 Container build cache

Not OpenRouter-specific but bites this code often: changes inside `container/agent-runner/src/` only take effect after `./container/build.sh`. The buildkit volume can hold stale `COPY` results — `--no-cache` alone does not suffice; pruning the builder is required for a guaranteed clean rebuild (per `nanoclaw/CLAUDE.md`).

---

## 7. Representative code excerpts

### 7.1 Provider config resolution

```ts
// prompt-router.ts:223
export function resolveOpenRouterProviderConfig(
  env: NodeJS.ProcessEnv = process.env,
): FreeProviderConfig {
  const authToken = env.OPENROUTER_API_KEY;
  if (!authToken) {
    throw new Error('OPENROUTER_API_KEY environment variable is required');
  }
  return {
    baseUrl: env.OPENROUTER_BASE_URL ?? 'https://openrouter.ai/api/v1',
    authToken,
  };
}
```

### 7.2 Candidate list with override + ranked + safety net

```ts
// prompt-router.ts:283
export async function resolveFreeModelCandidates(
  provider: FreeProviderConfig,
  overrideModel: string = process.env.ROUTER_SIMPLE_MODEL || '',
): Promise<string[]> {
  const candidates: string[] = [];
  if (overrideModel) candidates.push(overrideModel);
  const rankedModels = await fetchFreeCodingModels(provider.baseUrl, provider.authToken);
  candidates.push(...rankedModels);
  candidates.push('openrouter/free');
  return uniqueModels(candidates);
}
```

### 7.3 Stateless text completion

```ts
// prompt-router.ts:303
async function callModel(
  baseUrl, apiKey, model, systemPrompt, userPrompt, maxTokens = 2048,
): Promise<string> {
  const response = await fetch(`${baseUrl}/chat/completions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` },
    body: JSON.stringify({
      model,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt },
      ],
      max_tokens: maxTokens,
    }),
  });
  if (!response.ok) {
    const errorText = await response.text().catch(() => '(no body)');
    throw new Error(`${response.status}: ${errorText}`);
  }
  const data = await response.json();
  const content = data.choices?.[0]?.message?.content;
  if (!content) throw new Error('empty response');
  return sanitizeToolCallLeakage(content);
}
```

### 7.4 Tool-calling loop

```ts
// prompt-router.ts:500
async function callModelWithTools(
  baseUrl, apiKey, model, systemPrompt, userPrompt, maxTokens = 4096,
): Promise<string> {
  const messages: ChatMessage[] = [
    { role: 'system', content: systemPrompt },
    { role: 'user', content: userPrompt },
  ];

  for (let iteration = 0; iteration < MAX_TOOL_ITERATIONS; iteration++) {
    const response = await fetch(`${baseUrl}/chat/completions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({ model, messages, max_tokens: maxTokens, tools: FREE_MODEL_TOOLS }),
    });
    if (!response.ok) {
      const errorText = await response.text().catch(() => '(no body)');
      throw new Error(`${response.status}: ${errorText}`);
    }
    const data = await response.json();
    const assistantMessage = data.choices?.[0]?.message;
    if (!assistantMessage) throw new Error('empty response');

    const historyMsg: ChatMessage = { role: 'assistant', content: assistantMessage.content || null };
    if (assistantMessage.tool_calls?.length) historyMsg.tool_calls = assistantMessage.tool_calls;
    messages.push(historyMsg);

    if (!assistantMessage.tool_calls?.length) {
      const content = assistantMessage.content;
      if (!content) throw new Error('empty response with no tool calls');
      return sanitizeToolCallLeakage(content);
    }
    for (let i = 0; i < assistantMessage.tool_calls.length; i++) {
      const toolCall = assistantMessage.tool_calls[i];
      if (!toolCall.id) toolCall.id = `call_${iteration}_${i}`;
      const result = await executeToolCall(toolCall);
      messages.push({ role: 'tool', tool_call_id: toolCall.id, content: result });
    }
  }
  // Cap reached — return last assistant text (if any) sanitized.
}
```

### 7.5 Routing decision

```ts
// prompt-router.ts:203
export function selectExecutionPlan(input: RouteSelectionInput): ExecutionPlan {
  if (input.routerMode === 'complex-free') return { kind: 'sdk-free', reason: 'router mode complex-free' };
  if (input.routerMode === 'simple-complex' && input.hasOpenRouterKey && !input.isScheduledTask) {
    const decision = classifyPrompt(input.prompt);
    return decision.tier === 'simple'
      ? { kind: 'simple-free', reason: decision.reason }
      : { kind: 'sdk-default', reason: decision.reason };
  }
  return { kind: 'sdk-default', reason: 'default SDK path' };
}
```

### 7.6 Degenerate-output guard

```ts
// free-harness.ts:831
export function isDegenerate(text: string): boolean {
  const t = text.trim();
  if (!t) return false;
  if (/(.)\1{49,}/s.test(t)) return true;
  if (/(.{1,4})\1{24,}/s.test(t)) return true;
  if (t.length > 500) {
    const uniq = new Set(t).size;
    if (uniq < 15) return true;
  }
  return false;
}
```

---

## 8. Tests

| File | Coverage |
|------|----------|
| `container/agent-runner/src/prompt-router.test.ts` | `selectExecutionPlan` matrix; classifier; candidate ordering; 429 → `openrouter/free` fallback (`:193`); session-compat between paid/free |
| `container/agent-runner/src/free-harness.test.ts` | Plan parsing, scratchpad I/O, `isPlaceholder`, `isDegenerate`, stall hash, model-ladder fallback, tool dispatch (`bash`/`send_message`/`send_media`) |
| `container/agent-runner/src/free-model-health.test.ts` | Outcome recording, demotion logic, exemption of `openrouter/free` |
| `nanoclaw/src/db.test.ts` | Persisted `SessionRecord` round-trip with `providerBaseUrl: 'https://openrouter.ai/api/v1'` |

Run:

```bash
# Host-side (vitest.config.ts)
cd nanoclaw && npm test

# Agent-runner (separate config inside the container directory)
cd nanoclaw/container/agent-runner && npx vitest run
```

After modifying any file under `container/agent-runner/src/`, also rebuild the container image (`./container/build.sh`) before exercising end-to-end — host tests will pass against the source but live behavior runs from the prior container layer until a rebuild.

---

## 9. Maintenance hot-spots

If you only update one or two things in this doc when revisiting OpenRouter behavior, update these:

1. **`PREFERRED_CODING_MODELS` in `prompt-router.ts:83`.** New free models appear and disappear monthly on OpenRouter. The ranking here directly determines first-try latency and quality.
2. **`sanitizeToolCallLeakage()` in `prompt-router.ts:443`.** Whenever a new model leaks a previously-unseen tool-call markup pattern, add a regex here, add a test in `prompt-router.test.ts`, then rebuild the container.
3. **`isDegenerate()` thresholds in `free-harness.ts:831`.** If false positives or new collapse modes appear, tune here.
4. **`free-model-health.ts` cooldown / max-failures.** Tune via the `NANOCLAW_FREE_HARNESS_*` env vars before changing defaults in code.

---

## 10. Why this design (one-paragraph summary)

OpenRouter is used as a **plurality of free coding models behind a single OpenAI-compatible endpoint**, not as a long-term provider relationship. The integration assumes free models are individually unreliable but collectively useful, and that any single model can fail in five different ways within a single turn (rate-limit, tool-leakage, degeneration, stall, silence). Rather than retry hard on one model, the harness fails fast and walks a ranked ladder, with `openrouter/free` as a permanent safety net and a per-group health log that demotes serial offenders. The Claude SDK is preserved for high-stakes turns, accessible only via explicit user opt-in (`cc-paid`) — there is no automatic escalation, by design.
