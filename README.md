# SkillShield

SkillShield is an open-source security scanner for AI agent skills.

Think `npm audit` for `SKILL.md` files across OpenClaw/ClawHub, Codex-style skills, and other AgentSkills-compatible ecosystems.

It detects:
- Prompt injection and instruction override patterns
- Data exfiltration behavior
- Credential harvesting patterns
- Metadata mismatches (`requires.env`, `requires.bins` vs real behavior)
- Suspicious network targets
- LLM-level malicious intent signals (Claude Sonnet 4.6)

## Why

`SKILL.md` files are executable intent for AI agents. A skill can look harmless in plain text while embedding malicious behavior in markdown instructions or supporting scripts.

SkillShield combines static scanning with LLM semantic analysis so teams can catch both:
- deterministic code/rule violations
- higher-level intent attacks and social engineering

## Install

### With pipx (recommended)

```bash
pipx install skillshield
```

### Local development install

```bash
git clone https://github.com/krahimov/skill-scanner.git
cd skill-scanner
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Quick Start

Scan one skill directory:

```bash
skillshield scan ./path/to/skill
```

Scan one file:

```bash
skillshield scan ./path/to/skill/SKILL.md
```

Scan many skills recursively:

```bash
skillshield scan ./skills --recursive --format json
```

Run without LLM:

```bash
skillshield scan ./skills --recursive --no-llm
```

Use deep LLM profile:

```bash
skillshield scan ./path/to/skill --deep
```

## LLM Configuration

Set your API key:

```bash
export ANTHROPIC_API_KEY=your_key_here
```

Supported env vars:
- `ANTHROPIC_API_KEY` or `SKILLSHIELD_LLM_API_KEY`
- `SKILLSHIELD_LLM_MODEL_BULK` (default: `claude-sonnet-4-6`)
- `SKILLSHIELD_LLM_MODEL_DEEP` (default: `claude-sonnet-4-6`)
- `SKILLSHIELD_LLM_TIMEOUT_S` (default: `30`)
- `SKILLSHIELD_LLM_MAX_OUTPUT_TOKENS` (default: `1600`)
- `SKILLSHIELD_CACHE_DIR` (optional cache location)

## Output and Exit Codes

- `--format terminal` prints a rich human-readable report
- `--format json` prints machine-readable scan results
- Exit code is non-zero if any `high` or `critical` findings are present

## TypeScript Skills

Yes, TypeScript-based agents are supported.

SkillShield scans:
- `SKILL.md` markdown content
- supporting files in the skill folder, including `.ts` and `.js`

This means TS agent skills are still evaluated for exfiltration, injection, metadata mismatch, and suspicious execution patterns.

## Development

Run tests:

```bash
pytest -q
```

Lint:

```bash
ruff check src tests
```

Build package:

```bash
uv build
```

## Project Status

Active development. Current release target is `0.1.x` with a focus on scanner accuracy, low false positives, and CI integration.
