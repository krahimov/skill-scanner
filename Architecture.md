Let me think through this end-to-end and put together a proper plan for you.Now I have a deep picture of the attack surface. Let me put together a complete blueprint for you.Here's the full blueprint. Let me start with the architecture:Here's the full plan for **SkillShield** — an open-source agent skills supply chain scanner.

---

## The Problem You're Solving

Skills are increasingly portable across agent ecosystems because many agents are adopting the open Agent Skills format — a SKILL.md file with metadata and freeform instructions plus optional scripts. This means a malicious skill isn't just an OpenClaw problem; it's a distribution mechanism that travels across any compatible agent. People don't expect a markdown file to be dangerous, and in agent ecosystems the line between reading instructions and executing them collapses.

The existing defenses are weak — ClawHub's VirusTotal integration catches known malware signatures but misses prompt injection, social engineering in markdown, and behavioral mismatches between declared and actual capabilities.

---

## Architecture (3 Layers)

**Layer 1 — Ingestion** (how skills get into the scanner):
- **CLI tool** (`skillshield scan ./my-skill/`) — local developer use, like `npm audit`
- **GitHub Action** — runs on PR, blocks merges if critical findings
- **ClawHub crawler** — batch-scan the public registry, build a public leaderboard
- **MCP Server** — acts as a real-time gate, intercepts `clawhub install` and scans before installation

**Layer 2 — Analysis Engine** (the core, where all the value is):
- **SKILL.md Parser** — parse YAML frontmatter + markdown body, extract declared env vars, bins, permissions, install specs
- **Static Analyzers** — use tree-sitter to parse any embedded code blocks (bash, Python, JS), regex patterns for known bad patterns (curl to unknown domains, base64-encoded payloads, obfuscated commands)
- **LLM Analyzer** — send the full skill text to Claude to detect prompt injection patterns, social engineering ("run this command as a prerequisite"), and hidden intent mismatches
- **Metadata Verifier** — compare what the skill *declares* (env vars, permissions) vs what it *actually does* in code. ClawHub's security analysis already checks that declared metadata matches actual behavior, but it's shallow — you go deeper

**Layer 3 — Output**:
- SARIF/JSON risk report (integrates with GitHub Security tab)
- Trust badge embeddable on ClawHub pages
- Block/alert for critical findings
- Web dashboard for org-wide visibility

---

## Detection Rules (What You're Scanning For)

Here are the specific threat categories, roughly ordered by severity:

**Critical:**
1. **Data exfiltration** — skill sends data to external URLs not declared in metadata (curl, fetch, requests to unknown domains)
2. **Credential harvesting** — skill accesses env vars or files it doesn't declare (reading `~/.ssh`, `~/.aws/credentials`, API keys)
3. **Remote code execution** — skill downloads and executes code from external sources
4. **ClickFix-style attacks** — using "prerequisites" as the social engineering wrapper to get users to run malicious commands

**High:**
5. **Prompt injection in markdown** — hidden instructions in the skill body that hijack the agent's behavior
6. **Tool poisoning** — skill description says one thing, but tool calls do something else
7. **Metadata mismatch** — undeclared env var access, undeclared binary usage, undeclared network calls
8. **Privilege escalation** — skill requests sandbox bypass or shell access without justification

**Medium:**
9. **Dependency confusion** — skill references packages that could be typosquatted
10. **Stale/abandoned skills** — no updates, known vulnerable dependencies
11. **Reputation signals** — new author, sudden popularity spike (gaming installs like "What Would Elon Do?")

---

## MVP Implementation Plan

### Week 1: Core Parser + Static Analysis

```
skillshield/
├── src/
│   ├── parser/
│   │   ├── skill_parser.py      # YAML frontmatter + markdown extraction
│   │   └── code_extractor.py    # Extract code blocks from markdown
│   ├── analyzers/
│   │   ├── static_rules.py      # Regex/AST pattern matching
│   │   ├── metadata_diff.py     # Declared vs actual behavior
│   │   ├── network_analyzer.py  # External URL/domain detection
│   │   └── llm_analyzer.py      # Claude-based intent analysis
│   ├── reporters/
│   │   ├── sarif.py             # SARIF output for GitHub
│   │   ├── json_report.py       # Structured JSON
│   │   └── terminal.py          # Pretty CLI output
│   └── cli.py                   # Click-based CLI entry point
├── rules/
│   └── default_rules.yaml       # Detection rule definitions
├── tests/
│   ├── fixtures/                # Known malicious + benign skills
│   └── test_analyzers.py
└── pyproject.toml
```

**Step 1** — Build the parser. Skills are SKILL.md files with YAML frontmatter. Parse out: `name`, `description`, `requires.env`, `requires.bins`, `metadata.openclaw.install`, and the full markdown body. Then extract all fenced code blocks with their language tags.

**Step 2** — Static rules engine. Use tree-sitter to parse extracted code blocks into ASTs. Write rules like:
- "Code references `OPENAI_API_KEY` but frontmatter doesn't declare it in `requires.env`" → metadata mismatch
- "Code contains `curl` to a domain not in the skill's declared network scope" → potential exfiltration
- "Code contains `base64 -d` piped to `bash`" → obfuscated execution
- "Markdown contains invisible unicode characters or zero-width spaces" → hidden prompt injection

**Step 3** — CLI. `skillshield scan ./path/to/skill` should output a colored terminal report with severity levels.

### Week 2: LLM Analyzer + GitHub Action

**Step 4** — LLM analyzer. Send the full SKILL.md to Claude with a system prompt that asks it to:
- Identify any prompt injection patterns
- Flag social engineering ("before using this skill, run the following command...")
- Detect intent mismatches between the skill description and what the code actually does
- Score overall risk (0-100)

This is where you get a massive edge over pure static analysis. Markdown-based skills are fundamentally *natural language* instructions, and only an LLM can reliably detect adversarial natural language.

**Step 5** — GitHub Action. Wrap the CLI in a GitHub Action that runs on PRs to skills repos:

```yaml
- uses: skillshield/scan-action@v1
  with:
    path: ./skills/
    fail-on: critical
    api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

### Week 3: ClawHub Crawler + Public Dashboard

**Step 6** — Crawl ClawHub's 5,700+ skills. Scan them all. Publish results on a public dashboard (a simple Next.js site) showing:
- Skills ranked by risk score
- Category breakdown (how many critical/high/medium across the registry)
- "Verified Safe" badge that skill authors can embed
- Trending risks (new attack patterns emerging)

This is your marketing engine. The dashboard *is* the content marketing.

### Week 4: MCP Server Gate

**Step 7** — Build an MCP server that acts as a proxy. When a user runs `clawhub install @author/skill`, the MCP server intercepts it, scans the skill in real-time, and either approves or blocks with a risk summary. This is the "production runtime" version of the tool.

---

## Tech Stack

You already have most of this from Fabrik:
- **tree-sitter** — AST parsing for code blocks (you're already using this)
- **Python + Click** — CLI framework
- **Claude API** — LLM-based analysis (Sonnet 4.6 for both bulk and deep analysis)
- **Next.js** — public dashboard (you know this from your Toronto real estate project)
- **GitHub Actions** — CI/CD integration
- **SARIF** — standard security reporting format that GitHub natively displays

---



---
