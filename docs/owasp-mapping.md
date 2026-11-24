# agentprobe × OWASP — the execution layer

Most AI-security tooling tests what a model **says**: can it be talked into
emitting a jailbreak, a leak, or a *proposed* dangerous action. agentprobe tests
what an agent **does**: whether a proposed action actually **executes past the
human-approval gate**. That distinction is where agentprobe sits in the OWASP
taxonomy — and it's the layer the prompt-level scanners stop short of.

> **One line:** prompt-level red-teamers (garak, promptfoo) test whether an agent
> can be *induced to propose* a forbidden action. agentprobe tests whether that
> action *executes past the authorization gate* — OWASP **LLM03 / ASI02 / ASI03**
> at the execution layer.

## Proposal layer vs. execution layer

```
user prompt ─▶ [ model reasons ] ─▶ proposes tool call ─▶ [ approval gate ] ─▶ EXECUTES
                     ▲                      ▲                      ▲
             garak / promptfoo        promptfoo          ◀── agentprobe ──▶
             (jailbreak, leak)     (excessive-agency:      (did the executed
                                    "claims to perform")    action match what
                                                            was approved?)
```

The prompt-level tools grade the model's **output/claim**. agentprobe drives the
live agent and inspects the **executed tool call and the gate decision** — the
step after the model has spoken and the human has (or hasn't) been asked.

## Mapping

OWASP IDs below follow the **2026** lists: the *Top 10 for LLM Applications 2026*
(`LLMxx`) and the *Top 10 for Agentic Applications 2026* (`ASIxx`). Excessive
Agency was `LLM06` in 2025 and was promoted to **`LLM03`** in 2026; the agentic
list splits its successors into `ASI02`/`ASI03`. Mappings are our reading of
which risk each probe exercises, at the execution layer.

| agentprobe | What it verifies (execution layer) | OWASP |
|---|---|---|
| **`s2`** command swap | the executed command equals the command the human approved (not a poisoned substitute) | **LLM03** Excessive Agency · **ASI02** Tool Misuse |
| **`s3`** RAG / retrieval poisoning | injected retrieved content does not drive an unapproved action | **LLM01** Prompt Injection (indirect) → LLM03 / ASI02 |
| **`s4`** subagent hijack | a subagent's action passes the *same* gate as the primary, not an ungated side channel | **ASI03** Identity/Privilege Abuse · ASI02 |
| **`s5`** edit-scope swap | edits stay within the files/scope the human authorized | **LLM03** Excessive Agency · **ASI02** Tool Misuse |
| **`s8`** auto-invocation map | each tool actually gets the gate it should — and the behaviour matches what the agent *claims* | **ASI02** Tool Misuse · **ASI03** (approval bypass) |
| **`GateOracle`** | the authorization gate itself, in isolation: block / approve / run-silently on adversarial commands | the control behind **ASI02 / ASI03** |

## How this complements the prompt-level tools

agentprobe is **not** a replacement for garak or promptfoo — it's the layer below
them. Use them for the "says" items and agentprobe for the "does" items:

| Concern | Tool |
|---|---|
| Prompt injection text, jailbreaks, toxic output, data leakage (LLM01, LLM02, …) | garak, promptfoo |
| Whether the model *proposes* an over-reaching action (LLM03, proposal layer) | promptfoo `excessive-agency` plugin |
| Whether that action **executes past the human-approval gate** (LLM03 / ASI02 / ASI03, execution layer) | **agentprobe** |

A thorough agentic red-team wants both: a proposal-layer scanner to see what the
model can be pushed to *say*, and agentprobe to see whether the authorization
boundary *holds when it tries to act*.

## Caveats

- OWASP's GenAI lists are versioned and renumber between editions; IDs here are
  the 2026 editions. Re-check against the current OWASP GenAI Security Project
  pages before quoting IDs in a report.
- These mappings are interpretive: a probe exercises the *execution-layer* facet
  of each risk, not the full risk category.
