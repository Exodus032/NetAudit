import { useEffect, useMemo, useState } from "react";
import { useGlossary } from "../../hooks/useGlossary";
import { ErrorState, SkeletonRows, EmptyState } from "../../components/common/States";
import type { GlossaryTerm } from "../../api/typesLearn";
import "./GlossaryView.css";

const CATEGORY_LABELS: Record<string, string> = {
  protocol: "Protocol",
  security: "Security",
  networking: "Networking",
  tool: "Tool",
};

const DIFFICULTY_LABELS: Record<string, string> = {
  beginner: "Beginner",
  intermediate: "Intermediate",
  advanced: "Advanced",
};

export function GlossaryView() {
  const { terms, loading, error, reload } = useGlossary();
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("");
  const [difficulty, setDifficulty] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return terms
      .filter((t) => (category ? t.category === category : true))
      .filter((t) => (difficulty ? t.difficulty === difficulty : true))
      .filter((t) => (q ? t.term.toLowerCase().includes(q) || t.short.toLowerCase().includes(q) || t.id.includes(q) : true))
      .sort((a, b) => a.term.localeCompare(b.term));
  }, [terms, query, category, difficulty]);

  const selected = useMemo(() => terms.find((t) => t.id === selectedId) ?? filtered[0] ?? null, [terms, selectedId, filtered]);

  // Keep the detail panel showing something sensible when filters change out
  // from under the current selection.
  useEffect(() => {
    if (selectedId && !filtered.some((t) => t.id === selectedId)) setSelectedId(null);
  }, [filtered, selectedId]);

  if (error) return <ErrorState title="Couldn't load the glossary" detail={error} action={<button onClick={reload}>Retry</button>} />;
  if (loading && terms.length === 0) return <SkeletonRows rows={10} height={28} />;

  return (
    <div>
      <section className="view-section">
        <div className="view-section-header">
          <span className="view-section-title">Glossary</span>
          <span className="glossary-count">{terms.length} terms</span>
        </div>
        <div className="panel glossary-toolbar">
          <input
            type="search"
            className="glossary-search"
            placeholder="Search terms…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            aria-label="Search glossary"
          />
          <select value={category} onChange={(e) => setCategory(e.target.value)} aria-label="Filter by category">
            <option value="">All categories</option>
            {Object.entries(CATEGORY_LABELS).map(([id, label]) => (
              <option key={id} value={id}>{label}</option>
            ))}
          </select>
          <select value={difficulty} onChange={(e) => setDifficulty(e.target.value)} aria-label="Filter by difficulty">
            <option value="">All levels</option>
            {Object.entries(DIFFICULTY_LABELS).map(([id, label]) => (
              <option key={id} value={id}>{label}</option>
            ))}
          </select>
        </div>
      </section>

      <section className="view-section glossary-grid">
        <div className="panel glossary-list-panel">
          {filtered.length === 0 && <EmptyState title="No terms match" detail="Try a different search or clear the filters." />}
          <ul className="glossary-list">
            {filtered.map((t) => (
              <li key={t.id}>
                <button
                  className={`glossary-list-item${selected?.id === t.id ? " active" : ""}`}
                  onClick={() => setSelectedId(t.id)}
                  aria-current={selected?.id === t.id ? "true" : undefined}
                >
                  <span className="glossary-list-term">{t.term}</span>
                  <span className="glossary-list-short">{t.short}</span>
                </button>
              </li>
            ))}
          </ul>
        </div>

        <div className="panel glossary-detail-panel">
          {selected ? (
            <GlossaryDetail term={selected} allTerms={terms} onSelect={setSelectedId} />
          ) : (
            <EmptyState title="Pick a term" detail="Select an entry from the list to see the full explanation." />
          )}
        </div>
      </section>
    </div>
  );
}

function GlossaryDetail({
  term,
  allTerms,
  onSelect,
}: {
  term: GlossaryTerm;
  allTerms: GlossaryTerm[];
  onSelect: (id: string) => void;
}) {
  const related = term.see_also.map((id) => allTerms.find((t) => t.id === id)).filter((t): t is GlossaryTerm => !!t);

  return (
    <div>
      <div className="glossary-detail-head">
        <h3 className="glossary-detail-term">
          {term.term}
          {term.expansion && <span className="glossary-detail-expansion"> — {term.expansion}</span>}
        </h3>
        <div className="glossary-detail-badges">
          <span className="chip">{CATEGORY_LABELS[term.category] ?? term.category}</span>
          <span className="chip">{DIFFICULTY_LABELS[term.difficulty] ?? term.difficulty}</span>
        </div>
      </div>

      <p className="glossary-detail-short">{term.short}</p>
      <p className="glossary-detail-body">{term.detail}</p>

      <div className="glossary-detail-why">
        <div className="glossary-detail-label">Why it matters</div>
        <p className="glossary-detail-body">{term.why_it_matters}</p>
      </div>

      {related.length > 0 && (
        <div className="glossary-detail-related">
          <div className="glossary-detail-label">Related terms</div>
          <div className="glossary-related-list">
            {related.map((r) => (
              <button key={r.id} className="glossary-related-chip" onClick={() => onSelect(r.id)}>
                {r.term}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
