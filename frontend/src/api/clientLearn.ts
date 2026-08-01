// Typed fetch wrapper for Part D — Learning mode (docs/API_CONTRACT_V3.md).
// Reuses the token/retry/fallback machinery from ./client.ts — this module
// adds no fetch logic of its own, only the D1-D6 endpoint functions.

import { ApiError, withFallback } from "./client";
import {
  mockExplain,
  mockGlossary,
  mockGlossaryTerm,
  mockLesson,
  mockLessons,
  mockPrioritisedFindings,
  mockTour,
} from "../mocks/serverLearn";
import type {
  Explanation,
  ExplainKind,
  GlossaryResponse,
  GlossaryTerm,
  Lesson,
  LessonsResponse,
  PrioritisedFindingsResponse,
  TourResponse,
} from "./typesLearn";

/** 404 from the real backend (or the mock's null) means "not found", which
 * every consumer here treats as a valid, non-error answer — not every lookup
 * is for an id known to exist (e.g. a glossary cross-link that's stale). */
async function orNullOn404<T>(p: Promise<T>): Promise<T | null> {
  try {
    return await p;
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return null;
    throw err;
  }
}

export function getGlossary(): Promise<GlossaryResponse> {
  return withFallback("/api/glossary", undefined, mockGlossary);
}

export function getGlossaryTerm(id: string): Promise<GlossaryTerm | null> {
  return orNullOn404(withFallback(`/api/glossary/${encodeURIComponent(id)}`, undefined, () => mockGlossaryTerm(id)));
}

export function getExplanation(kind: ExplainKind, id: string): Promise<Explanation | null> {
  return orNullOn404(
    withFallback(`/api/explain/${encodeURIComponent(kind)}/${encodeURIComponent(id)}`, undefined, () => mockExplain(kind, id)),
  );
}

export function getTour(): Promise<TourResponse> {
  return withFallback("/api/tour", undefined, mockTour);
}

export function getLessons(): Promise<LessonsResponse> {
  return withFallback("/api/lessons", undefined, mockLessons);
}

export function getLesson(id: string): Promise<Lesson | null> {
  return orNullOn404(withFallback(`/api/lessons/${encodeURIComponent(id)}`, undefined, () => mockLesson(id)));
}

export function getPrioritisedFindings(): Promise<PrioritisedFindingsResponse> {
  return withFallback("/api/findings/prioritised", undefined, mockPrioritisedFindings);
}
