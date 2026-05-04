# Decisions log

Chronological record of design and process decisions. Each entry:
date, what changed, why, where it's encoded.

## 2026-05-03

**Day 2: ground truth isolation rules added to CLAUDE.md** after
observing that real-world IR cases never come with a curated
briefing. Agent must operate from evidence alone.

Encoded as a new section "Ground truth isolation" in `CLAUDE.md`,
placed between "Hard rules" and "Architectural enforcement of
evidence integrity". Three rules:

1. `docs/dataset-inventory.md` is a human-only artifact, used post-run
   to score findings. The agent must never read it.
2. The agent reads nothing under `docs/` at runtime. Only
   `case-data/evidence/` (read-only) and `case-data/extractions/`
   (its own parsed outputs) are in scope.
3. MCP functions never accept arbitrary file paths. They take an
   `evidence_id` registered in `CASE.yaml` and resolve to the path
   internally — the agent cannot route itself into `docs/`, `.git/`,
   or the source tree.

Why this matters: the autonomy criterion (rubric tiebreaker) measures
the agent's ability to reason from raw evidence. A leaked briefing
turns "detection" into "memorization" and inflates the accuracy
report. These rules are architectural, not prompt-level — enforced
by which MCP tools exist and what they accept.

**Day 2: Week 3 task — schema-introspection test that fails the build
if any MCP tool exposes a free-form path field.** Owner:
lead/architect.

Why this matters: rule 3 above (MCP functions take only `evidence_id`,
never raw paths) is the structural lock on the case sandbox. If even
one tool accidentally exposes a `path: str` parameter, the guardrail
leaks silently. A schema-introspection test that walks every tool's
pydantic model and rejects free-form path fields turns the rule from
a convention into a build-time check. To be implemented during Week 3
when tool schemas are scaffolded.

**Day 2: Week 5 task — analyst subagent definitions must restrict
tool list to MCP calls only, no bare Read/Bash/filesystem access.**
Owner: AI/agent engineer.

Why this matters: CLAUDE.md rule 2 (the agent reads nothing under
`docs/` at runtime) is enforced on the MCP server side, but if an
analyst subagent inherits the parent's bare `Read` / `Bash` / generic
filesystem tools, it can bypass the MCP boundary and read `docs/`,
`.git/`, or the source tree directly. That makes rule 2 a prompt
guardrail for the subagents instead of an architectural one. When
subagent definitions are wired up in Week 5, each analyst's allowed
tool list must be explicitly restricted to the SIFT-Guard MCP tools —
no `Read`, no `Bash`, no `Grep` against the repo. To be encoded in
`agent/.claude/agents/*.md` (or the Python orchestrator's analyst
config if the fallback path is taken).

**Day 2: Week 8 pre-submission task — replace dev-convenience SSH +
sudo access to the SIFT VM with a documented MCP server transport.**
Owner: lead/architect.

Current development setup: Claude Code reaches the SIFT VM via
`ssh -p 2222 sansforensics@<wsl-default-gw>` with passwordless sudo on
the guest, used during Day-1 verification (e.g. running
`vol windows.info.Info` and `sha256sum` on the memory image).

Why this matters: this is fine for the team's dev loop but
unacceptable for a submission. The hackathon judges should not be
asked to grant the agent passwordless sudo over SSH to a VM in order
to reproduce results — it inflates the trust surface, makes the
"architectural guardrails > prompt guardrails" claim look hollow, and
turns the try-it-out instructions into a security incident waiting to
happen. Before submission, this access path must be replaced with a
documented MCP server transport: either (a) the MCP server runs
inside the SIFT VM and Claude Code talks to it over stdio piped
through SSH (no shell, no sudo, only the typed MCP protocol on the
wire), or (b) the MCP server binds a TCP port on the VM that the host
connects to, with an explicit allow-list and no shell access. The
README's try-it-out section must reflect whichever option is chosen
and must NOT require the operator to grant the agent passwordless
sudo on the SIFT VM.
