# CLAUDE.md — SkillShield

## Project Overview

SkillShield is an open-source security scanner for AI agent skills. Think "npm audit" for the agent skills ecosystem (OpenClaw/ClawHub, OpenAI Codex skills, and any agent using the AgentSkills SKILL.md format).

It detects prompt injection, data exfiltration, credential harvesting, metadata mismatches, and social engineering attacks hidden in agent skill files — combining static analysis with LLM-powered intent detection.

**Author:** Karim @ Fabrik Labs
**License:** Apache 2.0

---

## Architecture

```
skillshield/
├── src/skillshield/
│   ├── __init__.py
│   ├── cli.py                    # Click CLI entry point
│   ├── config.py                 # Settings, rule loading, API keys
│   ├── parser/
│   │   ├── __init__.py
│   │   ├── skill_parser.py       # YAML frontmatter + markdown body extraction
│   │   ├── code_extractor.py     # Fenced code block extraction with language tags
│   │   └── models.py             # Pydantic models for parsed skill data
│   ├── analyzers/
│   │   ├── __init__.py
│   │   ├── base.py               # Abstract base analyzer + Finding model
│   │   ├── static_rules.py       # Regex + AST pattern matching rules
│   │   ├── metadata_diff.py      # Declared vs actual behavior comparison
│   │   ├── network_analyzer.py   # External URL/domain/IP detection
│   │   ├── code_analyzer.py      # tree-sitter AST analysis of embedded code
│   │   ├── llm_analyzer.py       # Claude-based semantic intent analysis
│   │   └── reputation.py         # Author age, popularity anomalies, staleness
│   ├── rules/
│   │   ├── __init__.py
│   │   ├── engine.py             # Rule loading + matching engine
│   │   └── default_rules.yaml    # Built-in detection rule definitions
│   ├── reporters/
│   │   ├── __init__.py
│   │   ├── sarif.py              # SARIF 2.1.0 output (GitHub Security tab)
│   │   ├── json_report.py        # Structured JSON report
│   │   └── terminal.py           # Rich-powered colored CLI output
│   ├── crawler/
│   │   ├── __init__.py
│   │   ├── clawhub.py            # ClawHub registry crawler
│   │   └── github.py             # GitHub skills repo scanner
│   └── mcp/
│       ├── __init__.py
│       └── server.py             # MCP server for real-time install gating
├── tests/
│   ├── conftest.py
│   ├── fixtures/
│   │   ├── benign/               # Known-safe skills for false positive testing
│   │   ├── malicious/            # Known-bad skills (exfil, injection, etc.)
│   │   └── edge_cases/           # Unicode tricks, polyglot files, etc.
│   ├── test_parser.py
│   ├── test_static_rules.py
│   ├── test_metadata_diff.py
│   ├── test_network_analyzer.py
│   ├── test_llm_analyzer.py
│   └── test_cli.py
├── action/
│   ├── action.yml                # GitHub Action definition
│   └── entrypoint.sh
├── dashboard/                    # Next.js public dashboard (separate deploy)
│   └── ...
├── pyproject.toml
├── CLAUDE.md                     # This file
└── README.md
```

---

## Tech Stack

- **Language:** Python 3.11+
- **CLI:** Click + Rich (for colored terminal output)
- **Parsing:** PyYAML for frontmatter, markdown-it-py for markdown, tree-sitter for code ASTs
- **LLM:** Anthropic Claude API (Sonnet 4.6 for both bulk and deep analysis)
- **Models:** Pydantic v2 for all data models
- **Testing:** pytest + pytest-asyncio
- **Packaging:** pyproject.toml with hatchling build backend
- **Linting:** ruff (format + lint)
- **Type checking:** pyright (strict mode)
- **Dashboard:** Next.js 14 + Tailwind + shadcn/ui (in `dashboard/`)

---

## Commands

```bash
# Install in development mode
pip install -e ".[dev]"

# Run the CLI
skillshield scan ./path/to/skill/          # Scan a single skill directory
skillshield scan ./skills/ --recursive     # Scan all skills in a directory
skillshield scan ./skill/SKILL.md          # Scan a single SKILL.md file
skillshield scan --format sarif            # Output SARIF for GitHub
skillshield scan --format json             # Output structured JSON
skillshield scan --severity critical,high  # Only show critical/high findings
skillshield scan --no-llm                  # Skip LLM analysis (offline mode)

# Crawl and scan ClawHub registry
skillshield crawl clawhub --limit 100      # Scan top 100 ClawHub skills
skillshield crawl clawhub --all            # Scan entire registry

# Run tests
pytest                                      # All tests
pytest tests/test_static_rules.py          # Specific test file
pytest -k "test_exfiltration"              # Specific test
pytest --no-llm                            # Skip tests requiring API key

# Lint and format
ruff check src/ tests/
ruff format src/ tests/

# Type check
pyright src/
```

---

## Coding Conventions

### General
- All code must pass `ruff check` and `pyright --strict` with zero errors
- Use `async/await` for all I/O operations (file reads, API calls, network)
- Prefer composition over inheritance. Analyzers implement a protocol, not a base class
- Every public function has a docstring. Keep them concise — one line if possible
- No print statements. Use `logging` or Rich console for output
- All string literals use double quotes
- Imports are sorted by ruff (isort-compatible)

### Type Annotations
- Every function signature is fully typed. No `Any` without a comment explaining why
- Use `pathlib.Path` not `str` for file paths
- Use Pydantic models for structured data, dataclasses for simple value objects
- Prefer `collections.abc.Sequence` over `list` in function parameters

### Error Handling
- Never catch bare `Exception`. Catch specific exceptions
- Parsing failures should return partial results with warnings, not crash
- LLM analyzer failures should gracefully degrade — the tool must work offline
- Use custom exception classes in `src/skillshield/exceptions.py`

### Testing
- Every analyzer rule must have at least one test with a malicious fixture and one with a benign fixture
- Test fixtures go in `tests/fixtures/` as real SKILL.md files
- Use `pytest.mark.llm` for tests that require an API key — these are skipped in CI by default
- Target: 90%+ coverage on the analyzers module
- Use `pytest.mark.parametrize` for rule tests with multiple samples

### Naming
- Analyzers: `{what}_analyzer.py` (e.g., `network_analyzer.py`)
- Test files: `test_{module}.py`
- Rule IDs: `SS-{CATEGORY}-{NUMBER}` (e.g., `SS-EXFIL-001`, `SS-INJECT-003`)
- Finding severities: `critical`, `high`, `medium`, `low`, `info`

---

## Key Data Models

```python
# Parsed skill representation
class ParsedSkill(BaseModel):
    name: str
    description: str
    path: Path
    frontmatter: dict[str, Any]          # Raw YAML frontmatter
    declared_env_vars: list[str]          # From requires.env
    declared_bins: list[str]             # From requires.bins
    declared_permissions: list[str]      # From metadata.openclaw
    markdown_body: str                   # Full markdown content
    code_blocks: list[CodeBlock]         # Extracted code with language tags
    install_specs: list[InstallSpec]     # From metadata.openclaw.install
    supporting_files: list[Path]         # Other files in skill directory

# Analysis finding
class Finding(BaseModel):
    rule_id: str                         # e.g., "SS-EXFIL-001"
    severity: Severity                   # critical/high/medium/low/info
    title: str                           # Human-readable title
    description: str                     # What was found and why it's risky
    location: Location                   # File, line number, code snippet
    confidence: float                    # 0.0-1.0 confidence score
    category: Category                   # exfiltration/injection/metadata/etc.
    remediation: str | None              # How to fix it

# Scan result
class ScanResult(BaseModel):
    skill: ParsedSkill
    findings: list[Finding]
    risk_score: int                      # 0-100 aggregate score
    scan_duration_ms: int
    analyzers_run: list[str]
```

---

## Detection Rules Reference

### Critical (must block)
| Rule ID | Category | Description |
|---------|----------|-------------|
| SS-EXFIL-001 | Exfiltration | Code sends data to external URLs not in declared scope |
| SS-EXFIL-002 | Exfiltration | Code accesses env vars / files not declared in frontmatter |
| SS-CRED-001 | Credentials | Code reads SSH keys, AWS credentials, or known secret paths |
| SS-RCE-001 | Remote Code Exec | Code downloads and executes from external source |
| SS-RCE-002 | Remote Code Exec | base64-encoded payload piped to shell |
| SS-CLICK-001 | Social Engineering | ClickFix-style prerequisite commands in markdown |

### High
| Rule ID | Category | Description |
|---------|----------|-------------|
| SS-INJECT-001 | Prompt Injection | Hidden instructions in markdown (LLM-detected) |
| SS-INJECT-002 | Prompt Injection | Invisible unicode / zero-width characters |
| SS-INJECT-003 | Prompt Injection | Instruction override patterns ("ignore previous...") |
| SS-POISON-001 | Tool Poisoning | Description/name mismatch with actual behavior |
| SS-META-001 | Metadata | Undeclared env var access |
| SS-META-002 | Metadata | Undeclared binary usage |
| SS-META-003 | Metadata | Undeclared network calls |
| SS-PRIV-001 | Privilege | Requests sandbox bypass or unrestricted shell |

### Medium
| Rule ID | Category | Description |
|---------|----------|-------------|
| SS-DEP-001 | Dependency | Typosquatting risk in install specs |
| SS-DEP-002 | Dependency | Pinned to known vulnerable version |
| SS-REP-001 | Reputation | Author account < 7 days old |
| SS-REP-002 | Reputation | Abnormal popularity spike (gaming detection) |
| SS-STALE-001 | Maintenance | No updates in 90+ days with known issues |

---

## LLM Analyzer Guidelines

The LLM analyzer (`llm_analyzer.py`) sends skill content to Claude for semantic analysis. Key design decisions:

- **Use structured output.** Send a system prompt that asks Claude to respond in JSON with specific fields: `findings[]`, `risk_score`, `intent_summary`
- **Always include the full SKILL.md** — don't truncate. Skills are small (usually <2K tokens)
- **Use Sonnet 4.6 for bulk scans and deep analysis** (single-model strategy for consistency)
- **Cache results** by content hash to avoid re-scanning unchanged skills
- **Graceful degradation** — if API key is missing or API is down, skip LLM analysis and only return static findings. Never crash
- **Rate limiting** — respect Anthropic's rate limits. Use asyncio semaphore for concurrent scans
- **No secrets in prompts** — never include actual env var values, only variable names

System prompt template lives in `src/skillshield/prompts/analyze_skill.txt`. Keep it versioned and tested.

---

## MCP Server Design

The MCP server (`mcp/server.py`) provides real-time skill scanning as an MCP tool:

- Tool name: `scan_skill`
- Input: `{ "skill_path": string }` or `{ "clawhub_slug": string }`
- Output: Structured scan result with findings and risk score
- The server should be installable as a Claude Code / OpenClaw MCP server
- Use the `mcp` Python SDK (pip install mcp)

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | No | — | Required for LLM analyzer. Tool works without it (static-only mode) |
| `SKILLSHIELD_LLM_MODEL_BULK` | No | `claude-sonnet-4-6` | Model for bulk semantic analysis |
| `SKILLSHIELD_LLM_MODEL_DEEP` | No | `claude-sonnet-4-6` | Model for deep semantic analysis |
| `SKILLSHIELD_RULES_PATH` | No | Built-in | Path to custom rules YAML |
| `SKILLSHIELD_CACHE_DIR` | No | `~/.cache/skillshield` | Cache directory for LLM results |
| `SKILLSHIELD_LOG_LEVEL` | No | `INFO` | Logging level |
| `CLAWHUB_API_URL` | No | `https://api.clawhub.ai` | ClawHub API base URL for crawler |

---

## Git Conventions

- Branch naming: `feat/`, `fix/`, `refactor/`, `test/`, `docs/`
- Commit messages: conventional commits (`feat:`, `fix:`, `test:`, `docs:`, `refactor:`)
- PR titles should match the primary commit type
- Squash merge to main
- Tag releases as `v{major}.{minor}.{patch}`

---

## Important Context

- This project is part of the Fabrik Labs ecosystem. The open-source scanner is a top-of-funnel for Fabrik's paid agent evaluation platform
- Primary target ecosystem is OpenClaw/ClawHub, but the scanner should work with any SKILL.md-based agent skill format (including OpenAI Codex skills)
- The ClawHub registry has 5,700+ skills as of Feb 2026. We want to scan all of them and publish results on a public dashboard
- Security companies (Cisco, CrowdStrike, Trend Micro) have published research on OpenClaw vulnerabilities but nobody has shipped a practical open-source tool yet. Speed to market matters
- The SKILL.md format is a folder with a SKILL.md file (YAML frontmatter + markdown) plus optional supporting text files. Skills declare env vars, bins, and install specs in frontmatter. The markdown body contains natural language instructions that the agent reads and follows — which is why prompt injection in markdown is such a critical attack vector

---

## What NOT to Do

- Don't over-engineer the rule engine. Start with simple regex + tree-sitter + LLM. We can add Semgrep/CodeQL later
- Don't build the dashboard before the CLI works end-to-end. CLI is the MVP
- Don't try to sandbox and execute skills — that's Fabrik's job. SkillShield is static + semantic analysis only
- Don't hardcode OpenClaw-specific assumptions. The parser should handle the AgentSkills spec generically
- Don't store or log actual secret values found during scans. Log the variable name, not the value
