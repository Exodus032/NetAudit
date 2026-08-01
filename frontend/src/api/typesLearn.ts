// Types for Part D â€” Learning mode (docs/API_CONTRACT_V3.md).
// Hand-written to mirror backend/netaudit/learn/models.py field-for-field.
// Do not diverge from field names, enum values, or shapes documented there.

export type GlossaryCategory = "protocol" | "security" | "networking" | "tool";
export type Difficulty = "beginner" | "intermediate" | "advanced";
export type ExplainKind = "detector" | "rule" | "check" | "metric" | "field";
export type LessonCheckKind = "view_visited" | "filter_applied" | "element_clicked" | "manual";
export type LearnViewId = "overview" | "traffic-log" | "connections" | "recommendations" | "posture" | "threats";
export type FindingSource = "posture" | "recommendation" | "threat";
export type Effort = "low" | "medium" | "high";
export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface GlossaryTerm {
  id: string;
  term: string;
  expansion?: string | null;
  short: string;
  detail: string;
  why_it_matters: string;
  see_also: string[];
  category: GlossaryCategory;
  difficulty: Difficulty;
}

export interface GlossaryResponse {
  terms: GlossaryTerm[];
}

export interface WorkedExample {
  scenario: string;
  walkthrough: string[];
}

export interface Explanation {
  kind: ExplainKind;
  id: string;
  title: string;
  plain: string;
  how_it_decides: string;
  what_would_make_it_wrong: string;
  worked_example?: WorkedExample | null;
  glossary_terms: string[];
  learn_more?: string | null;
}

export interface TourStep {
  id: string;
  order: number;
  view: LearnViewId;
  target: string;
  title: string;
  body: string;
  glossary_terms: string[];
  action_hint?: string | null;
}

export interface TourResponse {
  steps: TourStep[];
}

export interface LessonCheck {
  kind: LessonCheckKind;
  value: string;
}

export interface LessonStep {
  order: number;
  instruction: string;
  explanation: string;
  check: LessonCheck;
  glossary_terms: string[];
}

export interface Lesson {
  id: string;
  title: string;
  summary: string;
  difficulty: Difficulty;
  estimated_minutes: number;
  prerequisites: string[];
  objectives: string[];
  steps: LessonStep[];
  uses_live_data: boolean;
}

export interface LessonsResponse {
  lessons: Lesson[];
}

export interface DeepLink {
  view: string;
  id: string;
}

export interface PrioritisedFinding {
  id: string;
  source: FindingSource;
  title: string;
  severity: Severity;
  impact_score: number;
  effort: Effort;
  observed?: string | null;
  priority_rank: number;
  why_first: string;
  one_line_fix: string;
  deep_link: DeepLink;
}

export interface PrioritisedFindingsResponse {
  generated_at: string;
  items: PrioritisedFinding[];
}
