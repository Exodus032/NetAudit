import { useMemo, useState } from "react";
import { usePosture } from "../../hooks/usePosture";
import { PostureScoreHero } from "./PostureScoreHero";
import { CheckRow } from "./CheckRow";
import { ErrorState, SkeletonRows } from "../../components/common/States";
import { CATEGORY_LABELS } from "../../mocks/postureCatalog";
import "./PostureView.css";

export function PostureView() {
  const [category, setCategory] = useState<string>("");
  const [hidePassing, setHidePassing] = useState(false);
  const { data, loading, error, rescanning, rescan } = usePosture({
    category: category || undefined,
    include_pass: hidePassing ? false : undefined,
  });

  const grouped = useMemo(() => {
    if (!data) return [];
    const byCat = new Map<string, typeof data.checks>();
    for (const c of data.checks) {
      if (!byCat.has(c.category)) byCat.set(c.category, []);
      byCat.get(c.category)!.push(c);
    }
    return Array.from(byCat.entries()).map(([id, checks]) => ({
      id,
      label: CATEGORY_LABELS[id] ?? id,
      checks,
    }));
  }, [data]);

  if (error) return <ErrorState title="Couldn't load security posture" detail={error} />;
  if (loading && !data) return <SkeletonRows rows={10} height={28} />;
  if (!data) return null;

  return (
    <div>
      <section className="view-section">
        <div className="panel">
          <PostureScoreHero
            score={data.score}
            grade={data.grade}
            counts={data.counts}
            categories={data.categories}
            generatedAt={data.generated_at}
          />
        </div>
      </section>

      <section className="view-section">
        <div className="posture-toolbar">
          <select
            className="posture-filter-select"
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            aria-label="Filter by category"
          >
            <option value="">All categories</option>
            {data.categories.map((c) => (
              <option key={c.id} value={c.id}>{c.label}</option>
            ))}
          </select>
          <label className="posture-toggle">
            <input type="checkbox" checked={hidePassing} onChange={(e) => setHidePassing(e.target.checked)} />
            Hide passing checks
          </label>
          <div className="posture-toolbar-spacer" />
          <button className="posture-rescan-btn" onClick={rescan} disabled={rescanning}>
            {rescanning ? "Rescanning…" : "Rescan"}
          </button>
        </div>

        {grouped.length === 0 && <ErrorState title="No checks match these filters" />}

        {grouped.map((group) => (
          <div key={group.id} className="posture-category-group">
            <div className="posture-category-heading">{group.label}</div>
            {group.checks.map((c) => (
              <CheckRow key={c.id} check={c} />
            ))}
          </div>
        ))}
      </section>
    </div>
  );
}
