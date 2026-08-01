import "./ExplainNetworkView.css";

type ChapterAction = {
  label: string;
  view: string;
};

type Chapter = {
  id: string;
  title: string;
  description: string;
  actions: ChapterAction[];
};

const CHAPTERS: Chapter[] = [
  {
    id: "overview",
    title: "Start with the overview",
    description:
      "The overview turns the latest observations into a short picture of what NetAudit found, so you can decide where to look next.",
    actions: [{ label: "Open overview", view: "overview" }],
  },
  {
    id: "traffic",
    title: "Follow traffic and connections",
    description:
      "Traffic is the data moving between this computer and other places. Connections show which programs, services, and devices are involved.",
    actions: [
      { label: "Open traffic log", view: "traffic" },
      { label: "Open connections and devices", view: "connections" },
    ],
  },
  {
    id: "findings",
    title: "Understand the findings",
    description:
      "Recommendations suggest practical improvements. Security posture checks your setup, while threats call out activity that may need closer attention.",
    actions: [
      { label: "Open recommended actions", view: "recommendations" },
      { label: "Open security posture", view: "posture" },
      { label: "Open threats", view: "threats" },
    ],
  },
  {
    id: "action",
    title: "Take one safe action at a time",
    description:
      "Read why a suggestion matters before changing anything. Start with a suggested fix you understand, then check the result after making the change.",
    actions: [{ label: "Review a suggested fix", view: "recommendations" }],
  },
];

interface ExplainNetworkViewProps {
  onNavigate?: (view: string) => void;
}

export function ExplainNetworkView({ onNavigate }: ExplainNetworkViewProps) {
  return (
    <div className="explain-network-view">
      <section className="explain-network-intro" aria-labelledby="explain-network-title">
        <h1 id="explain-network-title">What is my network doing?</h1>
        <p>
          NetAudit observes this computer's connections and security setup. It helps you see what is communicating, what
          needs attention, and where to learn more without making changes for you.
        </p>
        <aside className="explain-network-warning" aria-labelledby="explain-network-warning-title">
          <h2 id="explain-network-warning-title">What NetAudit can miss</h2>
          <p>
            Your capture tier changes what NetAudit can observe, so a tier with fewer details can leave some connections or
            activity unseen. NetAudit can only report what it captures and checks while it is running. A missing finding
            cannot prove that nothing is wrong.
          </p>
          <p>NetAudit never changes your system.</p>
        </aside>
      </section>

      <section className="explain-network-chapters" aria-label="Network explanation chapters">
        {CHAPTERS.map((chapter) => (
          <article className="explain-network-card" key={chapter.id}>
            <h2>{chapter.title}</h2>
            <p>{chapter.description}</p>
            <div className="explain-network-actions">
              {chapter.actions.map((action) => (
                <button key={action.label} onClick={() => onNavigate?.(action.view)}>
                  {action.label}
                </button>
              ))}
            </div>
          </article>
        ))}
      </section>
    </div>
  );
}
