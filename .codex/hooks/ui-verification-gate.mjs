import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const action = process.argv[2];
const input = JSON.parse(readFileSync(0, "utf8"));
const sessionId = input.session_id ?? "unknown-session";
const turnId = input.turn_id ?? "unknown-turn";
const key = createHash("sha256").update(`${sessionId}:${turnId}`).digest("hex");
const stateDir = join(tmpdir(), "codex-ui-verification");
const stateFile = join(stateDir, `${key}.json`);

function isUiEdit(toolInput) {
  const change = JSON.stringify(toolInput ?? "");
  return /(?:frontend[\\/].*\.(?:css|scss|sass|less|tsx|jsx|html)|\.(?:css|scss|sass|less))\b/i.test(change);
}

if (action === "mark") {
  if (isUiEdit(input.tool_input)) {
    mkdirSync(stateDir, { recursive: true });
    writeFileSync(stateFile, JSON.stringify({ sessionId, turnId }));
  }
  process.stdout.write("{}");
  process.exit(0);
}

if (action === "check") {
  if (!existsSync(stateFile)) {
    process.stdout.write("{}");
    process.exit(0);
  }

  // One continuation forces the agent to verify visually without trapping it
  // in a loop. The current stop hook is then allowed to complete the turn.
  if (input.stop_hook_active) {
    rmSync(stateFile, { force: true });
    process.stdout.write("{}");
    process.exit(0);
  }

  process.stdout.write(JSON.stringify({
    decision: "block",
    reason: "UI files changed in this turn. Before finishing, run the app and visually inspect the affected screen using the available browser or screenshot tool. Check the relevant desktop and narrow viewport, fix any issue you find, then report what you verified.",
  }));
  process.exit(0);
}

process.stderr.write("Expected action 'mark' or 'check'.\n");
process.exit(1);
