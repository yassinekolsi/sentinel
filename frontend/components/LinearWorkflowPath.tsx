"use client";

type Event = { type: string; payload: Record<string, unknown> };
type Step = { id: number; events: Event[]; decision?: Event; action: Record<string, unknown>; outcome: Event[] };

const object = (value: unknown): Record<string, unknown> => value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
const label = (value: unknown) => String(value ?? "").replaceAll("_", " ");

export default function LinearWorkflowPath({ steps, selected, onSelect }: { steps: Step[]; selected?: number; onSelect: (id: number) => void }) {
  return <section className="workflow-section linear-workflow" aria-label="Action workflow">
    <div className="workflow-heading"><h2>Workflow</h2><span>Click a step to inspect it</span></div>
    <div className="workflow-scroll"><div className="workflow-graph">
      {steps.map((step, index) => {
        const decision = step.decision?.payload;
        const verdict = String(decision?.decision ?? "context");
        const action = object(decision?.action);
        const resultEvent = step.outcome.find((event) => event.type === "retrieval_result") ?? step.outcome[0];
        const result = object(resultEvent?.payload.result);
        const detail = verdict === "block" ? "Action stopped" : String(result.title ?? result.id ?? resultEvent?.payload.tool ?? (resultEvent?.type === "model_output" ? "Response delivered" : ""));
        return <div className="workflow-unit" key={step.id}>
          <button className={"workflow-node " + (selected === step.id ? "selected " : "") + (verdict === "block" ? "stopped" : "")} onClick={() => onSelect(step.id)} aria-pressed={selected === step.id}>
            <span className="workflow-node-number">{String(step.id).padStart(2, "0")}</span>
            <span className="workflow-node-action">{step.id === 0 ? "User request" : label(action.tool ?? action.type ?? "Observation")}</span>
            <span className={"workflow-gate " + verdict}>{verdict === "context" ? "START" : verdict.toUpperCase()}</span>
            <span className="workflow-node-result">{detail}</span>
          </button>
          {index < steps.length - 1 && <span className="workflow-edge" aria-hidden="true" />}
        </div>;
      })}
    </div></div>
  </section>;
}
