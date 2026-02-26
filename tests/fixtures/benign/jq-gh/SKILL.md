---
name: jq-gh
description: GitHub reporting skill using local shell variables and jq filters.
metadata:
  openclaw:
    requires:
      bins:
        - gh
        - jq
---

# JQ + GH Skill

```bash
PR=55 REPO=owner/repo
gh pr view $PR --repo $REPO --json number,title,state \
  --jq '.[] | select(.state == "OPEN") | .title'
```
