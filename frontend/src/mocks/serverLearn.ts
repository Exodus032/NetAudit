// Mock handlers for Part D — Learning mode. Mirrors the style of ./server.ts:
// same delay() shape, same "read from state, return a plain response object"
// pattern. Content comes verbatim from backend/netaudit/learn/data/*.json
// (copied into ./data/learn/*.json) — this file does not retype any of it.
//
// D6 (`findings/prioritised`) has no static JSON fixture on the backend
// either — it's computed from live posture/recommendation/threat data via
// `backend/netaudit/learn/prioritise.py`. That ranking algorithm (severity
// base score, status/confidence multiplier, effort bonus, attack-path bonus,
// deterministic tie-break) is ported below field-for-field so the mock
// produces the same shape and the same kind of ranking a real backend would,
// sourced from the existing mock posture/recommendation/threat state in
// ./store.ts (read-only — this file does not modify that store).

import { mulberry32, randInt } from "./rng";
import { state } from "./store";
import type { PostureCheck, Recommendation, Threat } from "../api/types";
import type {
  Effort,
  Explanation,
  ExplainKind,
  FindingSource,
  GlossaryResponse,
  GlossaryTerm,
  Lesson,
  LessonsResponse,
  PrioritisedFinding,
  PrioritisedFindingsResponse,
  Severity,
  TourResponse,
} from "../api/typesLearn";

import glossaryData from "./data/learn/glossary.json";
import explanationsData from "./data/learn/explanations.json";
import tourData from "./data/learn/tour.json";
import lessonsData from "./data/learn/lessons.json";

const GLOSSARY = (glossaryData as { terms: GlossaryTerm[] }).terms;
const EXPLANATIONS = (explanationsData as { explanations: Explanation[] }).explanations;
const TOUR_STEPS = (tourData as TourResponse).steps;
const LESSONS = (lessonsData as { lessons: Lesson[] }).lessons;

const latency = () => randInt(mulberry32(Date.now() % 991), 40, 160);

function delay<T>(value: T): Promise<T> {
  return new Promise((resolve) => setTimeout(() => resolve(value), latency()));
}

// --- D1/D2: glossary -------------------------------------------------------

export function mockGlossary(): Promise<GlossaryResponse> {
  const terms = [...GLOSSARY].sort((a, b) => a.id.localeCompare(b.id));
  return delay({ terms });
}

export function mockGlossaryTerm(id: string): Promise<GlossaryTerm | null> {
  return delay(GLOSSARY.find((t) => t.id === id) ?? null);
}

// --- D3: explanations --------------------------------------------------------

export function mockExplain(kind: string, id: string): Promise<Explanation | null> {
  return delay(EXPLANATIONS.find((e) => e.kind === kind && e.id === id) ?? null);
}

// --- D4: tour ----------------------------------------------------------------

export function mockTour(): Promise<TourResponse> {
  const steps = [...TOUR_STEPS].sort((a, b) => a.order - b.order);
  return delay({ steps });
}

// --- D5: lessons ---------------------------------------------------------------

export function mockLessons(): Promise<LessonsResponse> {
  const lessons = [...LESSONS].sort((a, b) => a.id.localeCompare(b.id));
  return delay({ lessons });
}

export function mockLesson(id: string): Promise<Lesson | null> {
  return delay(LESSONS.find((l) => l.id === id) ?? null);
}

// --- D6: prioritised findings --------------------------------------------------
// Port of backend/netaudit/learn/prioritise.py — see that file for the full
// rationale behind each table. Kept numerically identical on purpose.

const SEVERITY_BASE: Record<Severity, number> = {
  critical: 92,
  high: 72,
  medium: 50,
  low: 28,
  info: 10,
};

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

const STATUS_MULTIPLIER: Record<string, number> = {
  fail: 1.0,
  warn: 0.6,
};

const EFFORT_BONUS: Record<Effort, number> = {
  low: 10,
  medium: 0,
  high: -10,
};

const SOURCE_TIEBREAK_RANK: Record<FindingSource, number> = {
  threat: 2,
  posture: 1,
  recommendation: 0,
};

const DEFAULT_VIEW_FOR_SOURCE: Record<FindingSource, string> = {
  posture: "posture",
  recommendation: "recommendations",
  threat: "threats",
};

// Explicit, small, documented table — identical to prioritise.py's
// ATTACK_PATH_BONUS. Anything not listed gets 0.
const ATTACK_PATH_BONUS: Record<string, number> = {
  smb_signing_required: 5,
  smb1_disabled: 6,
  llmnr_disabled: 5,
  netbios_disabled: 3,
  blank_passwords: 6,
  autologon_disabled: 5,
  guest_account_disabled: 3,
  high_risk_ports_open: 5,
  rdp_disabled_or_nla: 4,
  wpad_disabled: 3,
  wifi_encryption_strength: 4,
  wifi_autoconnect_open: 4,
  listening_exposed: 4,
  ssl3_disabled: 4,
};

interface RankInput {
  id: string;
  source: FindingSource;
  title: string;
  observed?: string | null;
  severity: Severity;
  status?: string; // posture only: "fail" | "warn"
  confidence?: number; // recommendation/threat only, 0-1
  effort?: Effort;
  one_line_fix?: string;
  deep_link_view?: string;
}

function multiplier(item: RankInput): number {
  if (item.source === "posture") {
    return STATUS_MULTIPLIER[item.status ?? "fail"] ?? 1.0;
  }
  if (item.confidence == null) return 1.0;
  return Math.max(0, Math.min(1, item.confidence));
}

function impactScore(item: RankInput): number {
  const base = SEVERITY_BASE[item.severity];
  const m = multiplier(item);
  const effort = item.effort ?? "medium";
  const bonus = ATTACK_PATH_BONUS[item.id] ?? 0;
  const score = Math.round(base * m) + EFFORT_BONUS[effort] + bonus;
  return Math.max(0, Math.min(100, score));
}

function whyFirst(item: RankInput): string {
  const effort = item.effort ?? "medium";
  const bonus = ATTACK_PATH_BONUS[item.id] ?? 0;
  const severityPhrase: Record<Severity, string> = {
    critical: "Critical severity",
    high: "High severity",
    medium: "Medium severity",
    low: "Low severity",
    info: "Informational",
  };
  const effortPhrase: Record<Effort, string> = {
    low: "a low-effort fix",
    medium: "a moderate-effort fix",
    high: "a high-effort fix",
  };
  const parts = [`${severityPhrase[item.severity]} and ${effortPhrase[effort]}.`];
  if (item.status === "warn") {
    parts.push("Currently a soft warning, not a confirmed failure, which is why it ranks below equivalent hard fails.");
  }
  if (bonus >= 5) {
    parts.push("It closes a well-known attack path that needs no special access (no credentials, no foothold) to exploit.");
  } else if (bonus > 0) {
    parts.push("It reduces exposure to a known, commonly-abused attack technique on this network.");
  }
  return parts.join(" ");
}

function rank(items: RankInput[]): PrioritisedFinding[] {
  const scored = items.map((item) => ({ item, score: impactScore(item) }));
  scored.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    const sevDiff = SEVERITY_RANK[b.item.severity] - SEVERITY_RANK[a.item.severity];
    if (sevDiff !== 0) return sevDiff;
    const srcDiff = SOURCE_TIEBREAK_RANK[b.item.source] - SOURCE_TIEBREAK_RANK[a.item.source];
    if (srcDiff !== 0) return srcDiff;
    return a.item.id < b.item.id ? -1 : a.item.id > b.item.id ? 1 : 0;
  });

  return scored.map(({ item, score }, i) => ({
    id: `${item.source}:${item.id}`,
    source: item.source,
    title: item.title,
    observed: item.observed ?? null,
    severity: item.severity,
    impact_score: score,
    effort: item.effort ?? "medium",
    priority_rank: i + 1,
    why_first: whyFirst(item),
    one_line_fix: item.one_line_fix || "See the deep link for the exact remediation steps.",
    deep_link: { view: item.deep_link_view || DEFAULT_VIEW_FOR_SOURCE[item.source], id: item.id },
  }));
}

// -- mapping the existing mock posture/recommendation/threat state into the
// shape prioritise.rank() expects. Effort isn't a field either source
// carries today, so it's estimated from the shape of the remediation itself
// (how many steps, whether admin rights are needed) — the same kind of
// judgment call the real backend's FindingsProvider implementation has to
// make when it wires up the real posture/rules/threat packages.

function postureEffort(check: PostureCheck): Effort {
  const cmds = check.remediation?.commands ?? [];
  if (cmds.length === 0) return "medium";
  if (cmds.length > 2) return "high";
  if (cmds.some((c) => c.requires_admin)) return "medium";
  return "low";
}

function postureOneLineFix(check: PostureCheck): string | undefined {
  return check.remediation?.commands?.[0]?.command || check.remediation?.summary || undefined;
}

function recommendationEffort(rec: Recommendation): Effort {
  if (rec.actions.some((a) => a.kind === "command" && !a.requires_admin)) return "low";
  if (rec.actions.some((a) => a.kind === "link")) return "low";
  if (rec.actions.length === 0) return "medium";
  return "medium";
}

function recommendationOneLineFix(rec: Recommendation): string | undefined {
  return rec.actions[0]?.detail || rec.actions[0]?.label || undefined;
}

function threatEffort(threat: Threat): Effort {
  if (threat.recommended_actions.some((a) => a.kind === "command" && !a.requires_admin)) return "low";
  if (threat.recommended_actions.length === 0) return "medium";
  return "medium";
}

function threatOneLineFix(threat: Threat): string | undefined {
  return threat.recommended_actions[0]?.detail || threat.recommended_actions[0]?.label || undefined;
}

export function mockPrioritisedFindings(): Promise<PrioritisedFindingsResponse> {
  const items: RankInput[] = [];

  for (const check of state.postureChecks) {
    if (check.status !== "fail" && check.status !== "warn") continue;
    items.push({
      id: check.id,
      source: "posture",
      title: check.title,
      severity: check.severity,
      status: check.status,
      effort: postureEffort(check),
      one_line_fix: postureOneLineFix(check),
    });
  }

  for (const rec of state.recommendations) {
    if (rec.dismissed) continue;
    items.push({
      id: rec.id,
      source: "recommendation",
      title: rec.title,
      severity: rec.severity,
      confidence: rec.confidence,
      effort: recommendationEffort(rec),
      one_line_fix: recommendationOneLineFix(rec),
    });
  }

  for (const threat of state.threats) {
    if (threat.status === "resolved") continue;
    items.push({
      id: threat.id,
      source: "threat",
      title: threat.title,
      severity: threat.severity,
      confidence: threat.confidence,
      effort: threatEffort(threat),
      one_line_fix: threatOneLineFix(threat),
    });
  }

  return delay({ generated_at: new Date().toISOString(), items: rank(items) });
}

// re-exported for consumers that need to validate a kind before calling the
// explain endpoint, mirroring backend router.py's _VALID_EXPLAIN_KINDS check.
export const VALID_EXPLAIN_KINDS: ExplainKind[] = ["detector", "rule", "check", "metric", "field"];
