"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { Activity, ArrowLeft, ArrowRight, Check, ChevronDown, Layers3, Pause, Play, ShieldAlert } from "lucide-react";
import runIndex from "@/data/index.json";
import WorkflowPath from "./WorkflowPath";
import LinearWorkflowPath from "./LinearWorkflowPath";

type Run = (typeof runIndex)[number];
type Event = { type: string; actor: string; run_id: string; step_id: number; seq: number; payload: Record<string, unknown>; provenance_refs?: string[] };
type Outcome = { run_id: string; scenario_id: string; attack_present: boolean; attack_success: boolean; task_success: boolean; termination: string; decisions?: unknown[] };
type Trace = { events: Event[]; metadata: { model: string; mode: string; attack_mode: string; outcomes: Outcome[]; exposure: Record<string, { exact_payload_observed: boolean }> } };
type Step = { id: number; events: Event[]; decision?: Event; action: Record<string, unknown>; outcome: Event[] };

const decisions = ["all", "allow", "block", "escalate", "rewrite"];
const caseName = (value: string) => value.replaceAll("_", " ");
const upper = (value?: unknown) => String(value ?? "").toUpperCase();
const asObject = (value: unknown): Record<string, unknown> => value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
const pretty = (value: unknown) => JSON.stringify(value, null, 2);

function stage(step: Step) {
  if (step.decision) return String(asObject(step.decision.payload.action).tool || asObject(step.decision.payload.action).type || "response").replaceAll("_", " ");
  if (step.id === 0) return "User request";
  return step.events.find((event) => event.type === "tool_result")?.type ?? "Observation";
}

function SummaryValue({ label, value, tone }: { label: string; value: string; tone?: string }) {
  return <div className={`summary-value ${tone ?? ""}`}><span>{label}</span><strong>{value}</strong></div>;
}

function DataPanel({ title, value, accent }: { title: string; value: unknown; accent?: string }) {
  return <section className={`data-panel ${accent ?? ""}`}><div className="data-panel-head">{title}</div><pre>{typeof value === "string" ? value : pretty(value)}</pre></section>;
}

export default function Observatory() {
  const [runId, setRunId] = useState("invoice-rules");
  const [trace, setTrace] = useState<Trace | null>(null);
  const [loadError, setLoadError] = useState("");
  const [caseId, setCaseId] = useState("");
  const [selected, setSelected] = useState<number | null>(null);
  const [playing, setPlaying] = useState(false);
  const [tab, setTab] = useState<"overview" | "events">("overview");
  const [menu, setMenu] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetch(`/api/runs/${runId}`, { cache: "no-store" })
      .then((response) => { if (!response.ok) throw new Error(`Trace ${response.status}`); return response.json() as Promise<Trace>; })
      .then((data) => {
        if (cancelled) return;
        setTrace(data);
        setCaseId(data.metadata.outcomes.find((item) => item.scenario_id === "enterprise_poisoned_invoice")?.run_id ?? data.metadata.outcomes[0]?.run_id ?? data.events[0]?.run_id ?? "");
        const focusRun = data.metadata.outcomes.find((item) => item.scenario_id === "enterprise_poisoned_invoice")?.run_id ?? data.metadata.outcomes[0]?.run_id;
        setSelected(data.events.find((event) => event.run_id === focusRun && event.type === "defense_decision" && event.payload.decision === "block")?.step_id ?? null);
        setLoadError("");
      })
      .catch((error: unknown) => { if (!cancelled) setLoadError(error instanceof Error ? error.message : "Trace unavailable"); });
    return () => { cancelled = true; };
  }, [runId]);

  const activeRun = runIndex.find((item) => item.id === runId) ?? runIndex[0];
  const outcome = trace?.metadata.outcomes.find((item) => item.run_id === caseId);
  const events = useMemo(() => trace?.events.filter((event) => event.run_id === caseId) ?? [], [trace, caseId]);
  const steps = useMemo(() => {
    const map = new Map<number, Event[]>();
    for (const event of events) map.set(event.step_id, [...(map.get(event.step_id) ?? []), event]);
    return Array.from(map, ([id, records]): Step => ({
      id, events: records, decision: records.find((event) => event.type === "defense_decision"),
      action: asObject(records.find((event) => event.type === "defense_decision")?.payload.action),
      outcome: records.filter((event) => ["tool_result", "retrieval_result", "model_output", "human_confirmation", "memory_write", "safety_feedback"].includes(event.type)),
    })).sort((a, b) => a.id - b.id);
  }, [events]);
  const visible = steps;
  const current = visible.find((step) => step.id === selected) ?? visible[0];
  const currentIndex = visible.findIndex((step) => step.id === current?.id);
  const counts = useMemo(() => Object.fromEntries(decisions.map((name) => [name, name === "all" ? steps.filter((step) => step.decision).length : steps.filter((step) => step.decision?.payload.decision === name).length])), [steps]);
  const goal = events.filter((event) => event.type === "user_message").map((event) => String(event.payload.text ?? "")).join("\n");
  const move = useCallback((delta: number) => { const next = visible[currentIndex + delta]; if (next) setSelected(next.id); }, [visible, currentIndex]);

  useEffect(() => {
    if (!playing || !visible.length) return;
    const timer = window.setInterval(() => {
      const index = visible.findIndex((step) => step.id === (selected ?? visible[0].id));
      if (index >= visible.length - 1) { setPlaying(false); return; }
      setSelected(visible[index + 1].id);
    }, 1800);
    return () => window.clearInterval(timer);
  }, [playing, selected, visible]);
  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if (["INPUT", "SELECT", "TEXTAREA"].includes((event.target as HTMLElement).tagName)) return;
      if (event.key === "ArrowRight") move(1);
      if (event.key === "ArrowLeft") move(-1);
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [move]);

  const decision = current?.decision?.payload;
  const decisionName = String(decision?.decision ?? "");
  const sources = (decision?.provenance as Array<{ id: string; provenance: Record<string, unknown> }> | undefined) ?? [];
  const untrustedSource = sources.find((record) => record.provenance.trust_level === "untrusted_external");
  const protectedSource = sources.find((record) => record.provenance.sensitivity === "restricted");
  const blockedDataFlow = decisionName === "block" && (decision?.reason_codes as string[] | undefined)?.includes("SENSITIVE_DATA_FLOW");

  return <div className="app-shell">
    <aside className={`sidebar ${menu ? "sidebar-open" : ""}`}>
      <div className="brand"><div className="brand-mark"><img src="/sentinel-shield.svg" alt="Sentinel shield" /></div><div><b>sentinel</b><span>action firewall</span></div></div>
      <div className="nav-link active"><Activity size={17} /> Traces <span className="nav-count">{runIndex.length}</span></div>
      <div className="nav-heading run-heading">RUNS</div>
      <div className="run-list">
        {runIndex.map((item: Run) => <button key={item.id} className={`run-link ${runId === item.id ? "chosen" : ""}`} onClick={() => { setRunId(item.id); setMenu(false); setPlaying(false); }}>
          <span className={`run-icon ${item.attacks > 0 ? "attack" : ""}`}>{item.attacks > 0 ? <ShieldAlert size={15} /> : <Check size={15} />}</span>
          <span className="run-text"><b>{item.title}</b></span>
        </button>)}
      </div>
    </aside>

    <div className="main-column">
      <header className="topbar"><div className="topbar-left"><button className="menu-button" onClick={() => setMenu(!menu)} aria-label="Toggle run navigation"><Layers3 size={20} /></button><span>Observatory</span><span className="crumb">/</span><strong>{activeRun.title}</strong></div></header>
      <main className="page">
        <div className="page-title"><h1>{activeRun.title}</h1><div className="top-actions"><button className="outline-button" onClick={() => setSelected(null)}>Reset view</button></div></div>
        {loadError && <div className="error-box">{loadError}</div>}
        <section className="metrics">
          <SummaryValue label="DECISIONS" value={String(counts.all ?? 0)} />
          <SummaryValue label="BLOCKED" value={String(counts.block ?? 0)} tone="red" />
          <SummaryValue label="ESCALATED" value={String(counts.escalate ?? 0)} tone="amber" />
          <SummaryValue label="REWRITTEN" value={String(counts.rewrite ?? 0)} tone="purple" />
        </section>
        <section className="workspace-card">
          <div className="case-bar"><div className="case-select-wrap"><span>CASE</span><select aria-label="Case" value={caseId} onChange={(event) => { setCaseId(event.target.value); setSelected(null); setPlaying(false); }}>{trace?.metadata.outcomes.map((item) => <option key={item.run_id} value={item.run_id}>{caseName(item.scenario_id)}</option>)}</select><ChevronDown size={16} /></div><div className="case-tags"><span className={outcome?.task_success ? "tag good" : "tag bad"}>TASK {outcome ? outcome.task_success ? "COMPLETE" : "INCOMPLETE" : "PENDING"}</span><span className={outcome?.attack_present ? outcome.attack_success ? "tag bad" : "tag good" : "tag neutral"}>{outcome?.attack_present ? outcome.attack_success ? "ATTACK SUCCEEDED" : "ATTACK PREVENTED" : "BENIGN TASK"}</span></div></div>
          <div className="goal-row"><span className="section-number">01</span><div><label>USER GOAL</label><p>{goal || "No user goal recorded"}</p></div></div>
          {runId === "invoice-rules" && outcome?.scenario_id === "enterprise_poisoned_invoice"
            ? <WorkflowPath key={caseId} steps={steps} selected={current?.id} outcome={outcome} onSelect={(id) => { setSelected(id); setPlaying(false); setTab("overview"); }} />
            : <LinearWorkflowPath steps={steps} selected={current?.id} onSelect={(id) => { setSelected(id); setPlaying(false); setTab("overview"); }} />}
          <div className="workspace-tabs"><button className={tab === "overview" ? "on" : ""} onClick={() => setTab("overview")}>Decision path</button><button className={tab === "events" ? "on" : ""} onClick={() => setTab("events")}>Full event stream <span>{events.length}</span></button></div>
          {tab === "overview" ? <>
            <div className="trace-toolbar"><div className="step-actions"><button aria-label="Previous step" disabled={currentIndex <= 0} onClick={() => move(-1)}><ArrowLeft size={16} /></button><button aria-label={playing ? "Pause replay" : "Play replay"} onClick={() => setPlaying(!playing)}>{playing ? <Pause size={16} /> : <Play size={16} />}</button><button aria-label="Next step" disabled={currentIndex < 0 || currentIndex >= visible.length - 1} onClick={() => move(1)}><ArrowRight size={16} /></button></div></div>
            <div className="trace-body">
              <div className="inspector">{current ? <><div className="inspector-head"><div><span className="overline">STEP {String(current.id).padStart(2, "0")}</span><h2>{stage(current)}</h2></div>{decisionName && <span className={`decision-badge ${decisionName}`}>{upper(decisionName)}</span>}</div>
                {current.decision ? <>{blockedDataFlow && <div className="boundary-path"><div><span>UNTRUSTED INPUT</span><strong>{String(untrustedSource?.provenance.source_id ?? "External source")}</strong></div><b>→</b><div><span>PROTECTED DATA</span><strong>{String(protectedSource?.provenance.source_id ?? "Restricted value")}</strong></div><b>→</b><div><span>OUTPUT BOUNDARY</span><strong>Blocked before delivery</strong></div></div>}<div className="flow-grid"><DataPanel title="CANDIDATE ACTION" value={decision?.action ?? {}} /><section className={`decision-panel ${decisionName}`}><div className="data-panel-head">FIREWALL DECISION</div><div className="decision-main">{upper(decisionName)}</div><div className="reason-list">{(decision?.reason_codes as string[] ?? []).map((reason) => <span key={reason}>{reason}</span>)}</div><div className="decision-stats"><div><span>RISK</span><strong>{String(decision?.risk_score ?? "-")}</strong></div><div><span>CONFIDENCE</span><strong>{String(decision?.confidence ?? "-")}</strong></div></div>{Boolean(decision?.explanation) && <p>{String(decision?.explanation)}</p>}</section><DataPanel title="WHAT HAPPENED" value={current.outcome.length ? current.outcome.map((event) => ({ event: event.type, ...event.payload })) : decisionName === "block" ? "Action stopped. No tool result in this step." : "No execution result recorded in this step."} /></div>
                  {Boolean(decision?.rewritten_action) && <DataPanel title="REPLACEMENT ACTION" value={decision?.rewritten_action} accent="replacement" />}
                  <section className="evidence-section"><div className="section-head"><span className="section-number">02</span><h3>Source and evidence</h3></div><div className="provenance-table"><div className="table-head"><span>SOURCE</span><span>TRUST</span><span>SENSITIVITY</span></div>{((decision?.provenance as Array<{ id: string; provenance: Record<string, unknown> }> ?? []).slice(-8)).map((record) => <div className="source-row" key={record.id}><span>{String(record.provenance.source_id ?? record.id)}</span><span>{caseName(String(record.provenance.trust_level ?? "unknown"))}</span><span>{caseName(String(record.provenance.sensitivity ?? "unknown"))}</span></div>)}</div><details><summary>Decision metadata</summary><pre>{pretty(decision?.metadata ?? {})}</pre></details></section>
                </> : <DataPanel title="RECORDED EVENTS" value={current.events.map((event) => ({ event: event.type, ...event.payload }))} />}
              </> : <div className="inspector-empty">Select a step</div>}</div></div>
          </> : <div className="event-stream">{events.map((event) => <details key={`${event.run_id}-${event.seq}`}><summary><span className="event-seq">{String(event.seq).padStart(3, "0")}</span><b>{caseName(event.type)}</b><span>{event.actor}</span><span>STEP {event.step_id}</span></summary><pre>{pretty(event.payload)}</pre></details>)}</div>}
        </section>
        <div className="result-strip"><div><span className="overline">TASK</span><strong>{outcome ? outcome.task_success ? "Completed" : "Incomplete" : "No result"}</strong></div><div><span className="overline">ATTACK</span><strong>{outcome?.attack_present ? outcome.attack_success ? "Succeeded" : "Prevented" : "No attack"}</strong></div></div>
      </main>
    </div>
  </div>;
}
