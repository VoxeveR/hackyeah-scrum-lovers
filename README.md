# hackyeah-scrum-lovers · SpireGate

we love scrum we cant code we can vibe

SpireGate is an AI control layer sitting between any agent and the model and tools.
The agent only changes the `base_url` to the gateway and receives a virtual key; only the gateway knows the real keys (OpenAI, Jev).

## Start

```bash
uv sync
make test          # 113 tests, no keys and no network, ~3 s
make demo          # KYC scenario without an attack (scripted model, Jev stub)
make demo-attack   # the same scenario, but the web page contains a hidden instruction for the AI
make demo-loop     # the service does not respond, the agent retries the same call in a loop
make serve &       # gateway + dashboard; then open /ui/#/engine (Engine page)
make load          # 100 real requests from a simulated fleet — visible flowing on the Engine page (or via the Start button)
```

With real models: `cp .env.example .env`, add `OPENAI_API_KEY` (and optionally `TYPESAFE_API_KEY` for Jev), then run `make demo-live`.
Without `TYPESAFE_API_KEY`, the gateway uses the System One stub by itself and writes this into the audit trail.

## Scenario 1: KYC agent

The user request is identical in both variants: “Prepare a KYC summary for client ACME-001, check online messages about them, and send the summary to ania@gs.com.”

The agent has three tools: `crm_get_client` (private data), `web_fetch` (untrusted content), and `send_email` (dispatch). For each request, the gateway:

1. **identifies the agent** from the virtual key and checks whether the model is on the allowlist,
2. **labels the session** from the conversation history: CRM result → `client_pii`, web result → `untrusted`,
3. **masks** IBAN, LEI, and PESEL (only valid checksum numbers) before sending data to the external model,
4. **checks every action** the model requests before the agent executes it.

| Variant | What happens | Who decides |
|---|---|---|
| `benign` | the email goes to ania@gs.com; the model sees only `[IBAN#1]`, `[PESEL#1]` | DET-FIN-ID-001 (redaction) |
| `attack` | the page instructs sending the file to kyc-review@acme-corp.com → Jev hides the page from the model; if it were allowed through, the rule blocks the send | S1-JEV-001 (Jev), IFC-TRIFECTA-001 (rule, security layer) |

The data-flow rule blocks the attack even after removing all detectors and Jev (see tests).

## Scenario 2: Claude Code, Codex, and custom apps (hooks, SDK)

The same policy works for agents that execute tools themselves:

| Client | How it connects | Details |
|---|---|---|
| Claude Code | `PreToolUse` / `PostToolUse` / `UserPromptSubmit` hooks → `hooks/spire_hook.py` | [`demo/claude-code/`](demo/claude-code/README.md) |
| Codex CLI | the same hooks in `config.toml` (format `codex`, blocked with exit 2) | [`demo/codex/config.toml`](demo/codex/config.toml), not live-tested |
| Custom application | `spiregate.sdk.Guard` → `POST /v1/decide` | example below |

The hook never responds with “allow”: a permitted action returns to the usual approval questions from the agent.
When the gateway does not respond, the hook and SDK fail closed. Claude Code traffic to Anthropic does not pass through SpireGate.

```python
from spiregate.sdk import Guard
guard = Guard(key="spire-demo-sdk", session_id="pay-1")

@guard.tool("send_email")
def send_email(to, subject, body): ...   # checked before execution; result reported afterward
```

## Dashboard

`make serve` prints the dashboard URL with the administrator token, for example `http://127.0.0.1:8787/ui/#token=…`.
You configure a fixed token in `.env` (`SPIRE_ADMIN_TOKEN=`). An agent key does not open the dashboard. The panel is in English.

| Page | What it shows |
|---|---|
| Overview | decisions and 30-minute trends, security state, rules in action, agents |
| **Engine** | live real requests: first the *Company policy* step (number of rules, rev; click to open Policy), then three paths: deterministic, deterministic + Jev, Jev alone; latency and cost of the gateway itself, Start/Stop button (simulated fleet movement, max 15 s) |
| Live | every decision from the audit chain; clicking shows signals, Jev probabilities, hash |
| **Policy** | rule editor: add from catalog, edit, delete, **import from company policy text**, signature feed tab |
| Budgets | usage limits per organization / desk / agent, spending by model, control layer cost, active loop safeguards |
| Playground | any action or tool result through the real decision path, including what the agent sees |
| Audit | chain verification, JSONL / CSV / OCSF export, policy reload history |

The dashboard has no external dependencies (works offline). Changes made from the dashboard replace only the changed rule block in the policy file (comments elsewhere remain), the whole file is validated before saving and written atomically, so the gateway never loads half an edit. Every change increments `policy_rev`.

### Policy editor and text import

The **Policy** page groups rules by the actor making the decision: *Deterministic*, *Deterministic + Jev*, *Jev*.
**+ Rule** opens the catalog of ready-made checks with a simple form (without CEL); the rule remembers the template and parameters, so it later reopens in the same form. Rules outside the catalog (for example Jev thresholds) have advanced editing.
Deletion requires a second click; invariants cannot be changed or removed.

**Import from text**: paste the company policy in plain language (PL or EN), and the gateway splits it into sentences and proposes rules. Anything that can be checked with certainty (data, domains, amounts, commands, hours) becomes a deterministic rule with parameters taken from the text. The rest (“do not share M&A information with people outside the team”) is evaluated by Jev literally based on the sentence in the policy. Nothing is saved until a human selects the proposed rules; what the policy already does is marked “already in the policy”. Budget-related sentences are shown as skipped: budgets are configured in the `budgets:` section of the policy file, not by rules. The server rebuilds rules from the template and parameters, so the browser cannot append arbitrary conditions to the file. Import works through matching rules (without LLM).

The catalog of checks (each is enabled only when the bank adds it to the policy):

| Group | Checks |
|---|---|
| Data (masking in results, optionally with Jev verification) | PESEL, IBAN, card number, LEI, ISIN, secrets and keys, NIP, REGON, SSN, routing number (ABA), CUSIP, SWIFT/BIC, email, phone. Numbers with a checksum are validated (`python-stdnum`), so accidental digit strings are not masked |
| Actions | sending only to specified domains, credentials, download-and-run, destructive commands (`rm -rf`, force push, `DROP TABLE`, `terraform destroy`), privilege escalation (`sudo`, `chmod 777`), installing packages, payments above a threshold, work hours and weekends, disallowed tools |
| Descriptive rules | any sentence from the company policy, evaluated by Jev for risky actions (review or block) |

## Policy

One file: [`policy/spiregate.policy.yaml`](policy/spiregate.policy.yaml). Changes take effect on the next request, without restarting.
A bad file is rejected, and the gateway continues operating on the last valid version. Controls `ACC-TOOL-001`, `IFC-TRIFECTA-001`, and `CTL-SELF-001` are invariants: they cannot be removed.

Rules come in three kinds:
- **Facts** (access, paths, data flow, amounts, hours, budgets): resolved by rules; Jev is not asked.
- **Semantic rules**: a rule with a `verify:` block. When the rule allows an action, Jev checks whether something was missed (for example, PESEL written in words, client data sent to an allowed host). `verify.when` narrows when to ask at all.
- **Descriptive rules**: Jev only (action compatibility with the instruction, commands hidden in content, sentences from company policy: `detector: systemone_rule` with a `rule` field). Their `when` is a scope; shell commands are excluded from command-alignment checks because deterministic controls handle them.

System One (Jev, eventually a local Laya) returns a probability, and the thresholds in the policy turn it into a decision:
Below `escalate_at` it approves; from `escalate_at` it routes to human review; from `block_at` it blocks.
Blocking the tool result (for example, a page with a hidden command) means the model never sees it. Jev never reverses a deterministic rule decision and is not asked when the rule has already blocked. When Jev does not respond, only the rules evaluated by it are escalated to review (`on_error`), not silently passed. All questions about one action go in a single call. Every rule in the file always runs (enforce); to disable a rule, remove it from the file — there are no monitor/off modes, because a control either protects or it does not.

## Budgets and cost

The `prices` and `budgets` sections in the policy file. Each rule has a scope (`org`, `desk:<name>`, `agent:<id>`, with `*` patterns), a rolling window (minute / hour / day), and any of the following limits: USD, tokens, requests, tool calls.

- **Reservation before the call.** The gateway reserves the worst case (estimated input + `max_tokens`) on each matching budget before asking the model. After the response, the reservation is converted into the actual cost. Parallel agents do not exceed the budget between verification and spending.
- **Failure without retry.** Exceeding the budget returns `403 budget_exceeded` with the budget name, scope, and renewal time.
- **Loop guard (LOOP-001).** The same tool with the same arguments triggers a block 4 times in 60 s, blocking that one call for 120 s. Other agent actions continue.
- **Local models** are accounted for in GPU seconds (`usd_per_gpu_second`), external ones in tokens.
- **Cost of the control layer.** Calls to System One are counted separately as a percentage of model cost.
- Restarting the gateway does not reset spending: budget state is reconstructed from the audit chain.

## Audit

`make audit` shows decisions, and `make verify` checks the hash chain in `var/audit.jsonl` (changing or deleting an entry = error).
