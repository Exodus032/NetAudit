// Integration surface for the student/learning-mode frontend. Nav ids are
// prefixed "learn-" so they can't collide with the main app's ViewId union.
//
// The view components are lazy-loaded so this package isn't part of the
// main chunk a professional-mode-only session never opens. App renders the
// active view directly with no Suspense boundary of its own, so each entry
// below wraps its lazy component in its own <Suspense> — a view here must
// never suspend into App. GuidedTour and useLearningMode stay eager: App
// mounts the tour at app level regardless of which view is active.

import { lazy, Suspense, type ComponentType } from "react";
import { SkeletonRows } from "../../components/common/States";

const LearnHomeView = lazy(() => import("./LearnHomeView").then((m) => ({ default: m.LearnHomeView })));
const GlossaryView = lazy(() => import("./GlossaryView").then((m) => ({ default: m.GlossaryView })));
const LessonsView = lazy(() => import("./LessonsView").then((m) => ({ default: m.LessonsView })));
const FixFirstView = lazy(() => import("./FixFirstView").then((m) => ({ default: m.FixFirstView })));
const ExplainNetworkView = lazy(() => import("./ExplainNetworkView").then((m) => ({ default: m.ExplainNetworkView })));

export const LEARN_NAV_ITEMS: { id: string; label: string; icon: string }[] = [
  { id: "learn-home", label: "Learn", icon: "◎" },
  { id: "learn-glossary", label: "Glossary", icon: "❖" },
  { id: "learn-lessons", label: "Lessons", icon: "◐" },
  { id: "learn-fix-first", label: "Fix this first", icon: "✚" },
];

type LearnViewProps = { onNavigate?: (v: string) => void };

// One Suspense-wrapped component per map entry, so a still-loading learn
// chunk never suspends past this boundary into App's own render.
function withSuspense(LazyView: ComponentType<LearnViewProps>): ComponentType<LearnViewProps> {
  return function SuspendedLearnView(props: LearnViewProps) {
    return (
      <Suspense fallback={<SkeletonRows />}>
        <LazyView {...props} />
      </Suspense>
    );
  };
}

export const LEARN_VIEWS: Record<string, ComponentType<LearnViewProps>> = {
  "learn-home": withSuspense(LearnHomeView),
  "learn-glossary": withSuspense(GlossaryView),
  "learn-lessons": withSuspense(LessonsView),
  "learn-fix-first": withSuspense(FixFirstView),
  "learn-explain-network": withSuspense(ExplainNetworkView),
};

export { GuidedTour } from "../../components/learn/GuidedTour";
export { useLearningMode } from "../../hooks/useLearningMode";
