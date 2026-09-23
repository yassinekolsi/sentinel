"use client";

import { useEffect, useMemo, useState } from "react";
import {
  Background, Controls, Handle, MarkerType, Position, ReactFlow,
  type Edge, type Node, type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

type Event = { type: string; payload: Record<string, unknown> };
type Step = { id: number; events: Event[]; decision?: Event; action: Record<string, unknown>; outcome: Event[] };
type Outcome = { task_success: boolean; attack_present: boolean; attack_success: boolean };
type FlowData = Record<string, unknown> & {
  stepId: number | null;
  title: string;
  detail: string;
  verdict: string;
  active: boolean;
  attention: boolean;
};
type FlowNode = Node<FlowData, "step">;

const object = (value: unknown): Record<string, unknown> => value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
const titleCase = (value: unknown) => String(value ?? "").replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());

function FlowCard({ data }: NodeProps<FlowNode>) {
  return <div className={"flow-card " + data.verdict + (data.active ? " active" : "") + (data.attention ? " attention" : "")}>
    <Handle type="target" id="left" position={Position.Left} className="flow-handle" />
    <Handle type="target" id="top" position={Position.Top} className="flow-handle" />
    <Handle type="target" id="right" position={Position.Right} className="flow-handle" />
    <div className="flow-card-top"><span>{data.stepId === null ? "END" : String(data.stepId).padStart(2, "0")}</span><b>{data.verdict === "context" ? "START" : data.verdict.toUpperCase()}</b></div>
    <strong>{data.title}</strong>
    <p>{data.detail}</p>
    <Handle type="source" id="right" position={Position.Right} className="flow-handle" />
    <Handle type="source" id="bottom" position={Position.Bottom} className="flow-handle" />
    <Handle type="source" id="left" position={Position.Left} className="flow-handle" />
  </div>;
}

const nodeTypes = { step: FlowCard };

function detailFor(step: Step): { text: string; attention: boolean } {
  const resultEvent = step.outcome.find((event) => event.type === "retrieval_result") ?? step.outcome[0];
  const result = object(resultEvent?.payload.result);
  const body = String(result.body ?? result.content ?? "");
  if (/note to the ai assistant/i.test(body)) return { text: "Untrusted instruction in delivery note", attention: true };
  if (body.includes("[redacted]")) return { text: "Restricted source returned", attention: true };
  if (result.title) return { text: String(result.title), attention: false };
  if (result.id) return { text: String(result.id), attention: false };
  if (resultEvent?.type === "model_output") return { text: "Response delivered", attention: false };
  if (step.decision?.payload.decision === "block") return { text: "Stopped before execution", attention: true };
  if (step.id === 0) return { text: "Original task", attention: false };
  return { text: String(step.action.tool ?? step.action.type ?? "Action recorded").replaceAll("_", " "), attention: false };
}

export default function WorkflowPath({ steps, selected, onSelect, outcome }: { steps: Step[]; selected?: number; onSelect: (id: number) => void; outcome?: Outcome }) {
  const [mobile, setMobile] = useState(false);
  useEffect(() => {
    const query = window.matchMedia("(max-width: 740px)");
    const update = () => setMobile(query.matches);
    update();
    query.addEventListener("change", update);
    return () => query.removeEventListener("change", update);
  }, []);
  const { nodes, edges } = useMemo(() => {
    const total = steps.length + (outcome ? 1 : 0);
    const columns = total > 9 ? 4 : 3;
    const position = (index: number) => {
      const row = Math.floor(index / columns);
      const slot = index % columns;
      const column = row % 2 === 0 ? slot : columns - 1 - slot;
      return { x: column * 300, y: row * 190 };
    };
    const flowNodes: FlowNode[] = steps.map((step, index) => {
      const decision = step.decision?.payload;
      const action = object(decision?.action);
      const detail = detailFor(step);
      return {
        id: String(step.id), type: "step", position: position(index),
        data: {
          stepId: step.id,
          title: step.id === 0 ? "User request" : titleCase(action.tool ?? action.type ?? "Observation"),
          detail: detail.text,
          verdict: String(decision?.decision ?? "context"),
          active: step.id === selected,
          attention: detail.attention,
        },
      };
    });
    if (outcome) flowNodes.push({
      id: "outcome", type: "step", position: position(steps.length),
      data: {
        stepId: null, title: "Outcome",
        detail: (outcome.attack_present ? outcome.attack_success ? "Attack succeeded" : "Attack prevented" : "Benign run") + " · " + (outcome.task_success ? "task complete" : "task incomplete"),
        verdict: outcome.attack_present && outcome.attack_success ? "block" : outcome.task_success ? "result" : "incomplete",
        active: false, attention: false,
      },
    });
    const flowEdges: Edge[] = flowNodes.slice(0, -1).map((node, index) => {
      const row = Math.floor(index / columns);
      const turns = Math.floor((index + 1) / columns) > row;
      return {
        id: "edge-" + index, source: node.id, target: flowNodes[index + 1].id,
        sourceHandle: turns ? "bottom" : row % 2 === 0 ? "right" : "left",
        targetHandle: turns ? "top" : row % 2 === 0 ? "left" : "right",
        type: "smoothstep",
        style: { stroke: node.data.verdict === "block" ? "#c83f50" : "#4a94bd", strokeWidth: 2.5 },
        markerEnd: { type: MarkerType.ArrowClosed, color: node.data.verdict === "block" ? "#c83f50" : "#4a94bd" },
      };
    });
    return { nodes: flowNodes, edges: flowEdges };
  }, [steps, selected, outcome]);

  return <section className="workflow-section" aria-label="Action workflow">
    <div className="workflow-heading"><h2>Workflow</h2><span>Click a node to inspect the step</span></div>
    <div className="workflow-canvas">
      <ReactFlow<FlowNode, Edge>
        key={mobile ? "mobile" : "desktop"}
        nodes={nodes} edges={edges} nodeTypes={nodeTypes}
        fitView={!mobile} fitViewOptions={{ padding: 0.12, maxZoom: 1.05 }}
        defaultViewport={mobile ? { x: 20, y: 45, zoom: 0.9 } : undefined}
        minZoom={0.3} maxZoom={1.6}
        nodesDraggable={false} nodesConnectable={false}
        onNodeClick={(_, node) => { if (node.data.stepId !== null) onSelect(node.data.stepId); }}
        proOptions={{ hideAttribution: true }}
      >
        <Background gap={20} size={1} color="#dceaf1" />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  </section>;
}
