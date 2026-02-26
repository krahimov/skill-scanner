---
name: git-helper
description: Helper commands for common git operations like interactive rebase, cherry-pick, and log formatting.
---

# Git Helper

Common git shortcuts.

## Rebase last N commits

```bash
git rebase -i HEAD~$1
```

## Pretty log

```bash
git log --oneline --graph --decorate -20
```
