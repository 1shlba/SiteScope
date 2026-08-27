<!--
Keep this short. Two or three sentences per section is plenty.
What matters is that someone reading this in three months understands why.
-->

## What this changes

<!-- One or two sentences, written for a person, not a diff. -->

## Why

<!-- The problem this solves, or the reason it is worth doing.
     This is the part that is genuinely hard to reconstruct later. -->

## How to check it

<!-- How a reviewer can see it working. For example:
     1. Run `python tests\vulnerable_target.py 8099`
     2. Scan http://127.0.0.1:8099/
     3. The new finding appears with severity High -->

## Checklist

- [ ] `pytest` passes locally
- [ ] Added or updated a test covering this change
- [ ] Added a line to `CHANGELOG.md` under `[Unreleased]`
- [ ] No scan data, database files or generated reports included
- [ ] If a new security check: registered in `checks/__init__.py` **and** added
      to `hiddenimports` in `build/sitescope.spec`
