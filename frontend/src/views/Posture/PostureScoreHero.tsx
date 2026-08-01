import type { PostureCategorySummary, PostureCounts } from "../../api/types";
import { ShareBar } from "../../components/common/ShareBar";
import "./PostureScoreHero.css";

function gradeColor(grade: string): string {
  switch (grade) {
    case "A":
    case "B":
      return "var(--status-good)";
    case "C":
      return "var(--status-warning)";
    case "D":
      return "var(--status-serious)";
    default:
      return "var(--status-critical)";
  }
}

function scoreColor(score: number): string {
  if (score >= 80) return "var(--status-good)";
  if (score >= 60) return "var(--status-warning)";
  if (score >= 40) return "var(--status-serious)";
  return "var(--status-critical)";
}

export function PostureScoreHero({
  score,
  grade,
  counts,
  categories,
  generatedAt,
}: {
  score: number;
  grade: string;
  counts: PostureCounts;
  categories: PostureCategorySummary[];
  generatedAt: string;
}) {
  return (
    <div className="posture-hero" data-tour="posture-score">
      <div className="posture-hero-score">
        <div className="posture-hero-figure" style={{ color: gradeColor(grade) }}>
          {score}
          <span className="posture-hero-grade">{grade}</span>
        </div>
        <div className="posture-hero-label">Overall posture score</div>
        <div className="posture-hero-generated">Last scanned {new Date(generatedAt).toLocaleString(undefined, { hour12: false })}</div>
        <div className="posture-hero-counts">
          <span className="posture-count posture-count-pass">{counts.pass} pass</span>
          <span className="posture-count posture-count-warn">{counts.warn} warn</span>
          <span className="posture-count posture-count-fail">{counts.fail} fail</span>
          <span className="posture-count posture-count-neutral">{counts.error} couldn't check</span>
          <span className="posture-count posture-count-neutral">{counts.skipped} skipped</span>
        </div>
      </div>
      <div className="posture-hero-categories">
        {categories.map((cat) => (
          <div key={cat.id} className="posture-cat-row">
            <span className="posture-cat-label">{cat.label}</span>
            <ShareBar share={cat.score / 100} color={scoreColor(cat.score)} label={`${cat.label} score ${cat.score}`} />
          </div>
        ))}
      </div>
    </div>
  );
}
