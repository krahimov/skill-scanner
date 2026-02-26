---
name: process-env-check
description: Demonstrates process.env access without reading .env files.
metadata:
  openclaw:
    requires:
      env:
        - DATABASE_URL
      bins:
        - node
---

# Process Env Check

```js
const dbUrl = process.env.DATABASE_URL;
console.log(!!dbUrl);
```
