---
name: demo-signet
description: Demo the Countersign gate on `rm`. Creates two empty files at the repo root, shows them, deletes each with its own `rm` (each one asks the device), then shows what is left. User-invoked only.
disable-model-invocation: true
allowed-tools: Bash
---

# /demo-signet

Do exactly the four steps below, in order, each as its own Bash call. Do not
plan, explore, read files, or explain. Do not wrap anything in a script: the
hook inspects the Bash command text, so an `rm` hidden inside a script file
would not be gated, and the gate is the whole point.

Every `rm` goes through the Countersign hook and waits for the device. Run it
once, as written. If it is refused or times out, do not retry, do not use
another tool or another verb to remove the file, and do not touch the daemon.
The refusal is a result, not an error to work around.

1. Create both files, empty, and show them:

   ```bash
   touch sample.txt sample-script.py && ls -l sample.txt sample-script.py
   ```

2. Delete the first file, alone:

   ```bash
   rm sample.txt
   ```

3. Delete the second file, alone:

   ```bash
   rm sample-script.py
   ```

4. Show what is left:

   ```bash
   ls -l sample.txt sample-script.py
   ```

Then reply in at most four short lines: which files were created, which
deletes were approved, and which files still exist. If a file still exists,
say so plainly and say why (refused, timed out, no daemon). Nothing else.
