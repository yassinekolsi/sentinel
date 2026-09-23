"use client";

type Event = { type: string; payload: Record<string, unknown> };
type Step = { id: number; events: Event[]; decision?: Event; action: Record<string, unknown>; outcome: Event[] };

const object = (value: unknown): Record<string, unknown> => value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
const label = (value: unknown) => String(value ?? "").replaceAll("_", " ");

function eventSummary(event: Event | undefined): string {
  if (!event) return "No execution recorded";
  const payload = event.payload;
  const result = object(payload.result);
  if (event.type === "retrieval_result") return String(result.title ?? result.id ?? payload.tool ?? "Source returned");
  if (event.type === "model_output") return "Response delivered";
  if (event.type === "tool_result") return String(payload.tool ?? "Tool completed");
  return label(event.type);
}

export default function WorkflowPath({ steps, selected, onSelect }: { steps: Step[]; selected?: number; onSelect: (id: number) => void }) {
  return <section className="workflow-section" aria-label="Recorded workflow">
    <div className="workflow-heading"><h2>Workflow</h2><span>Click a step to inspect its evidence</span></div>
    <div className="workflow-lanes" aria-hidden="true"><span>AGENT</span><span>FIREWALL</span><span>RESULT</span></div>
    <div className="workflow-scroll"><div className="workflow-graph">
      {steps.map((step, index) => {
        const decision = step.decision?.payload;
        const verdict = String(decision?.decision ?? "context");
        const action = object(decision?.action);
        const actionName = step.id === 0 ? "User request" : String(action.tool ?? action.type ?? "Observation");
        const result = step.outcome[0] ?? step.events.find((event) => event.type === "retrieval_result" || event.type === "model_output");
        const stopped = verdict === "block";
        return <div className="workflow-unit" key={step.id}>
          <button className={"workflow-node " + (selected === step.id ? "selected " : "") + (stopped ? "stopped" : "")} onClick={() => onSelect(step.id)} aria-pressed={selected === step.id}>
            <span className="workflow-node-number">{String(step.id).padStart(2, "0")}</span>
            <span className="workflow-node-action">{label(actionName)}</span>
            <span className={"workflow-gate " + verdict}>{verdict === "context" ? "START" : verdict.toUpperCase()}</span>
            <span className="workflow-node-result">{stopped ? "Action stopped" : eventSummary(result)}</span>
          </button>
          {index < steps.length - 1 && <span className="workflow-edge" aria-hidden="true" />}
        </div>;
      })}
    </div></div>
  </section>;
}
