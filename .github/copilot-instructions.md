# Copilot Instructions (Submodule: sck-core-api)

- Tech: Python package (FastAPI dev server only; production behind API Gateway).
- Precedence: Prefer this file and submodule docs first. If absent, use root: `../../.github/copilot-instructions.md`.
- Backend conventions: See `../sck-core-ui/docs/backend-code-style.md` (S3 prefixes, MagicS3Bucket, Lambda ProxyEvent, envelopes).
- API envelopes: For non-OAuth JSON APIs consumed by UI use `{ status, code, data, metadata, message }`. OAuth endpoints follow RFC 6749.
- UI alignment: If responses affect UI, align with `../sck-core-ui/docs/ui-style-guide.md` and `../sck-core-ui/docs/auth-session-and-storage.md`.
- Dev-only metrics: prometheus-client must remain a dev dependency; gate local endpoints with env flags.
- On conflicts with root vs local, prefer local and surface a contradiction warning.

## RST Documentation Requirements
**MANDATORY**: All docstrings must be RST-compatible for Sphinx documentation generation:
- Use proper RST syntax: `::` for code blocks (not markdown triple backticks)
- Code blocks must be indented 4+ spaces relative to preceding text
- Add blank line after `::` before code content
- Bullet lists must end with blank line before continuing text
- Use RST field lists for parameters: `:param name: description`
- Use RST directives: `.. note::`, `.. warning::`, etc.
- Test docstrings with Sphinx build - code is source of truth, not docstrings

## Contradiction Detection
- Compare prompts against:
  - `../sck-core-ui/docs/backend-code-style.md` (S3 usage, presigned URLs, Lambda, API envelopes)
  - Root precedence in `../../.github/copilot-instructions.md`
  - If UI-visible responses are involved, also `../sck-core-ui/docs/ui-style-guide.md` and `../sck-core-ui/docs/auth-session-and-storage.md`
- If a prompt contradicts any rule, respond with:
  1. Warning: "Your instruction '[quote]' conflicts with [rule] in [source file]."
  2. Options: "Modify prompt to align with [rule], or update [source file]."
  3. Example: "Prompt suggests attaching Authorization to S3 presigned PUT, but backend-code-style.md and UI auth docs prohibit it. Omit Authorization for presigned S3 calls."

## Standalone clone note
If you cloned this submodule by itself (outside the parent monorepo), refer to these docs online:
- UI/backend conventions: https://github.com/eitssg/simple-cloud-kit/tree/develop/sck-core-ui/docs
- Root Copilot guidance: https://github.com/eitssg/simple-cloud-kit/blob/develop/.github/copilot-instructions.md



# Repo guardrails for Copilot (Python)

Runtime model
- All Python in this repo runs in AWS Lambda. Handlers must be synchronous.
- Do NOT introduce `async def`/`await` in Lambda code. Use threads if concurrency is necessary.

Local dev
- The local FastAPI router may await handlers, but the handler interfaces remain sync.

Networking/HTTP
- Use `httpx.Client` (blocking). Avoid `httpx.AsyncClient` and `asyncio`.

OAuth modules (e.g., `core_api/oauth/*`)
- Keep everything synchronous.
- For redirects, construct with just `RedirectResponse(url=...)` — the code is implied/forced by the type; do not pass `code` or `status_code`.

General guidance
- Prefer small, stateless functions suitable for Lambda.
- If a suggestion conflicts with these rules, prefer these rules.
