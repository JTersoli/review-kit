# Review: <PR title>

**Verdict:** Request changes (N critical, N high) | Approve with comments

## Scope
- Read: <files>
- Ran: `npm test` (<result>), `npm run typecheck` (<result>), `node scan.mjs` (<N> candidates, <N> confirmed, <N> discarded)
- Not reviewed: <files or areas>, because <time / outside the auth path>

## Findings (most severe first)
1. **[Critical]** `<file>:<line>` — <what>. **Impact:** <who can do what>. **Repro:** <steps or test>. **Fix:** <one line>.
2. **[High]** ...
3. **[Medium]** ...
4. **[Low]** ...

## Looks wrong but is fine
- `<file>:<line>` — <why it is OK, and what would make it not OK>

## Questions for the author
- ...

## Scanner hits I discarded
- `<rule>` at `<file>:<line>` — <why it does not apply here>
