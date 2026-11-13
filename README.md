# Hodor

**[English](README.md) | [中文](README.zh-CN.md)**

> Hodor — hold the door between your AI agent and your secrets.

Hodor is a CLI-first credential broker for AI agents. It keeps everything an agent needs to *use* but must never *see* — sudo passwords, SSH credentials, API keys, tokens — and performs privileged actions on the agent's behalf.

In an agent's world there are only **aliases** (`{{openai}}`, `{{sudo}}`) and execution results. Real secrets exist only inside Hodor's process memory and behind your fingerprint or master passphrase.

## Status

Early development (M1: local vault, object model, audit chain, policy engine, output scrubbing). See [docs/DESIGN.md](docs/DESIGN.md) for the full architecture, requirements (R1–R24), and roadmap.

## Core guarantees

- **No secret ever reaches the agent's context** — not in tool output, not in argv, not in files it can read.
- **Out-of-band approval** — native pinentry dialogs with an anti-phishing phrase; approval binds to the exact command hash.
- **Tamper-evident audit** — append-only hash chain whose head is stored inside the encrypted vault.
- **Hard sudo blacklist** — password resets, sudoers edits, shadow reads, and privilege-escalation vectors are refused regardless of configuration.

## Install

Not yet published — this is a development repository. Build from source:

```bash
cargo install --path crates/hodor-cli
```

## Quick start

```bash
hodor init                 # create the vault: master passphrase + anti-phishing phrase
hodor add key openai       # store a secret under an alias (prompted, never via argv)
hodor add sudo             # store the sudo password
hodor run -- curl -s -H "Authorization: Bearer {{openai}}" https://api.example.com
hodor audit --verify       # verify the tamper-evident audit chain
```

## License

Apache-2.0
