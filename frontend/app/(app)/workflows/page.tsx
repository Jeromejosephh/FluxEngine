"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "@/src/api";
import { LoadingSpinner } from "@/components/LoadingSpinner";

interface Workflow {
  id: number; name: string; description: string;
  status: "draft" | "active" | "archived"; created_at: string;
}
interface Step {
  id: number; name: string; step_type: string;
  config: Record<string, unknown>; order: number; workflow_id: number;
}
interface Table { id: number; name: string; }
interface Schedule { cron_expr: string; is_enabled: boolean; next_run_at: string | null; }

const STATUS_COLORS: Record<string, string> = {
  draft: "bg-[#37373d] text-[#858585]",
  active: "bg-[#1e3a2f] text-[#4ec9b0]",
  archived: "bg-[#3a1e1e] text-[#f14c4c]",
};

const STEP_COLORS: Record<string, string> = {
  query: "bg-[#1e2a3a] text-[#569cd6]",
  condition: "bg-[#2a2a1e] text-[#dcdcaa]",
  action: "bg-[#2a1e3a] text-[#c586c0]",
  transform: "bg-[#37373d] text-[#858585]",
};

const inputCls = "bg-[#3c3c3c] border border-[#3e3e42] rounded px-3 py-2 text-sm text-[#d4d4d4] focus:outline-none focus:border-[#007acc] placeholder-[#858585] w-full";
const btnPrimary = "bg-[#007acc] text-white rounded px-3 py-1.5 text-sm font-medium hover:bg-[#0069ac] disabled:opacity-50 transition-colors";
const btnSecondary = "border border-[#3e3e42] rounded px-3 py-1.5 text-sm text-[#d4d4d4] hover:bg-[#37373d] transition-colors";

export default function WorkflowsPage() {
  const qc = useQueryClient();
  const [selected, setSelected] = useState<Workflow | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [runResult, setRunResult] = useState<Record<string, unknown> | null>(null);
  const [runError, setRunError] = useState("");

  // Edit workflow
  const [showEditWorkflow, setShowEditWorkflow] = useState(false);
  const [editName, setEditName] = useState("");
  const [editDesc, setEditDesc] = useState("");

  // Schedule
  const [showSchedule, setShowSchedule] = useState(false);
  const [cronExpr, setCronExpr] = useState("0 9 * * *");
  const [scheduleEnabled, setScheduleEnabled] = useState(true);
  const [scheduleError, setScheduleError] = useState("");

  // Add step
  const [stepName, setStepName] = useState("");
  const [stepType, setStepType] = useState("query");
  const [stepTableId, setStepTableId] = useState("");
  const [stepColumn, setStepColumn] = useState("");
  const [stepOp, setStepOp] = useState("eq");
  const [stepValue, setStepValue] = useState("");
  const [stepWebhook, setStepWebhook] = useState("");
  const [showAddStep, setShowAddStep] = useState(false);
  const [stepError, setStepError] = useState("");

  const { data: workflows = [], isLoading, isError } = useQuery<Workflow[]>({
    queryKey: ["workflows"],
    queryFn: () => api.get("/api/workflows/"),
  });

  const { data: steps = [] } = useQuery<Step[]>({
    queryKey: ["steps", selected?.id],
    queryFn: () => api.get(`/api/workflows/${selected!.id}/steps/`),
    enabled: !!selected,
  });

  const { data: tables = [] } = useQuery<Table[]>({
    queryKey: ["tables"],
    queryFn: () => api.get("/api/tables/"),
  });

  const { data: schedule } = useQuery<Schedule>({
    queryKey: ["schedule", selected?.id],
    queryFn: () => api.get(`/api/workflows/${selected!.id}/schedule/`),
    enabled: !!selected,
    retry: false,
  });

  const createWorkflow = useMutation({
    mutationFn: () => api.post("/api/workflows/", { name: newName, description: newDesc }),
    onSuccess: (w: unknown) => {
      qc.invalidateQueries({ queryKey: ["workflows"] });
      setSelected(w as Workflow);
      setShowCreate(false); setNewName(""); setNewDesc("");
    },
  });

  const updateWorkflow = useMutation({
    mutationFn: (data: { name?: string; description?: string; status?: string }) =>
      api.put(`/api/workflows/${selected!.id}/`, data),
    onSuccess: (updated: unknown) => {
      qc.invalidateQueries({ queryKey: ["workflows"] });
      setSelected(updated as Workflow);
      setShowEditWorkflow(false);
    },
  });

  const deleteWorkflow = useMutation({
    mutationFn: (id: number) => api.delete(`/api/workflows/${id}/`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["workflows"] });
      setSelected(null);
    },
  });

  const addStep = useMutation({
    mutationFn: () => {
      let config: Record<string, unknown> = {};
      if (stepType === "query") config = { table_id: Number(stepTableId) };
      if (stepType === "condition") config = { column: stepColumn, op: stepOp, value: stepValue };
      if (stepType === "action") config = { webhook_url: stepWebhook };
      if (stepType === "transform") config = { select_columns: [] };
      return api.post(`/api/workflows/${selected!.id}/steps/`, {
        name: stepName, step_type: stepType,
        workflow_id: selected!.id, config, order: steps.length,
      });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["steps", selected?.id] });
      setShowAddStep(false); setStepName(""); setStepType("query");
      setStepTableId(""); setStepColumn(""); setStepOp("eq");
      setStepValue(""); setStepWebhook(""); setStepError("");
    },
    onError: (e: Error) => setStepError(e.message),
  });

  const runWorkflow = useMutation({
    mutationFn: () => api.post(`/api/workflows/${selected!.id}/run/`, {}),
    onSuccess: (res) => { setRunResult(res as Record<string, unknown>); setRunError(""); },
    onError: (e: Error) => setRunError(e.message),
  });

  const saveSchedule = useMutation({
    mutationFn: () =>
      api.post(`/api/workflows/${selected!.id}/schedule/`, { cron_expr: cronExpr, is_enabled: scheduleEnabled }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["schedule", selected?.id] });
      setShowSchedule(false);
      setScheduleError("");
    },
    onError: (e: Error) => setScheduleError(e.message),
  });

  if (isLoading) return <LoadingSpinner />;
  if (isError) return <p className="text-sm text-[#f14c4c]">Failed to load workflows.</p>;

  return (
    <div className="flex gap-6 h-full">
      {/* Workflow list */}
      <div className="w-48 shrink-0">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-xs font-medium text-[#858585] uppercase tracking-wider">Workflows</h2>
          <button onClick={() => setShowCreate(true)} className="text-xs text-[#007acc] hover:text-[#4db8ff]">+ New</button>
        </div>
        <div className="flex flex-col gap-0.5">
          {workflows.map((w) => (
            <button
              key={w.id}
              onClick={() => { setSelected(w); setRunResult(null); setRunError(""); }}
              className={`text-left px-3 py-1.5 rounded text-sm truncate transition-colors ${
                selected?.id === w.id
                  ? "bg-[#37373d] text-[#d4d4d4] border-l-2 border-[#007acc]"
                  : "text-[#858585] hover:text-[#d4d4d4] hover:bg-[#2a2d2e]"
              }`}
            >
              {w.name}
            </button>
          ))}
          {workflows.length === 0 && <p className="text-xs text-[#858585] px-1">No workflows yet</p>}
        </div>
      </div>

      {/* Workflow detail */}
      <div className="flex-1 min-w-0">
        {!selected ? (
          <div className="flex items-center justify-center h-64 text-[#858585] text-sm">
            Select a workflow or create one
          </div>
        ) : (
          <div>
            <div className="flex items-center justify-between mb-5">
              <div className="flex items-center gap-3">
                <h1 className="text-base font-semibold text-[#d4d4d4]">{selected.name}</h1>
                <span className={`text-xs px-2 py-0.5 rounded font-medium ${STATUS_COLORS[selected.status]}`}>
                  {selected.status}
                </span>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => {
                    setEditName(selected.name);
                    setEditDesc(selected.description ?? "");
                    setShowEditWorkflow(true);
                  }}
                  className={btnSecondary}
                >
                  Edit
                </button>
                <button
                  onClick={() => {
                    if (schedule) {
                      setCronExpr(schedule.cron_expr);
                      setScheduleEnabled(schedule.is_enabled);
                    }
                    setShowSchedule(true);
                  }}
                  className={btnSecondary}
                >
                  Schedule
                </button>
                {selected.status === "draft" && (
                  <button onClick={() => updateWorkflow.mutate({ status: "active" })} className={btnSecondary}>
                    Activate
                  </button>
                )}
                {selected.status === "active" && (
                  <button
                    onClick={() => runWorkflow.mutate()}
                    disabled={runWorkflow.isPending}
                    className="bg-[#1e3a2f] text-[#4ec9b0] border border-[#2a5a3f] rounded px-3 py-1.5 text-sm font-medium hover:bg-[#2a5a3f] disabled:opacity-50 transition-colors"
                  >
                    {runWorkflow.isPending ? "Running..." : "▶ Run now"}
                  </button>
                )}
                <button onClick={() => deleteWorkflow.mutate(selected.id)} className="text-sm text-[#f14c4c] hover:text-red-400 px-2 py-1.5">
                  Delete
                </button>
              </div>
            </div>

            {/* Schedule info */}
            {schedule && (
              <div className="mb-4 px-3 py-2 rounded border border-[#3e3e42] bg-[#2d2d2d] flex items-center gap-3">
                <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${schedule.is_enabled ? "bg-[#4ec9b0]" : "bg-[#858585]"}`} />
                <span className="text-xs text-[#858585]">
                  Schedule: <span className="font-mono text-[#d4d4d4]">{schedule.cron_expr}</span>
                  {schedule.next_run_at && (
                    <span className="ml-2">· Next: {new Date(schedule.next_run_at).toLocaleString()}</span>
                  )}
                </span>
              </div>
            )}

            {/* Steps */}
            <div className="mb-4">
              <div className="flex items-center justify-between mb-2">
                <p className="text-xs font-medium text-[#858585] uppercase tracking-wider">Steps</p>
                <button onClick={() => setShowAddStep(true)} className="text-xs text-[#007acc] hover:text-[#4db8ff]">+ Add step</button>
              </div>
              <div className="flex flex-col gap-2">
                {steps.sort((a, b) => a.order - b.order).map((step, i) => (
                  <div key={step.id} className="border border-[#3e3e42] rounded-lg px-4 py-3 bg-[#252526]">
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-[#4e4e4e] w-4">{i + 1}</span>
                      <span className={`text-xs px-2 py-0.5 rounded font-medium ${STEP_COLORS[step.step_type] ?? STEP_COLORS.transform}`}>
                        {step.step_type}
                      </span>
                      <span className="text-sm text-[#d4d4d4] font-medium">{step.name}</span>
                    </div>
                    <p className="text-xs text-[#4e4e4e] mt-1 ml-6 font-mono">
                      {JSON.stringify(step.config)}
                    </p>
                  </div>
                ))}
                {steps.length === 0 && (
                  <p className="text-sm text-[#858585]">No steps yet — add one to get started</p>
                )}
              </div>
            </div>

            {/* Run result */}
            {runError && <p className="text-sm text-[#f14c4c] mb-3">{runError}</p>}
            {runResult && (
              <div className="border border-[#3e3e42] rounded-lg p-4 bg-[#252526]">
                <p className="text-sm font-medium text-[#d4d4d4] mb-2">
                  Last run —{" "}
                  <span className={runResult.success ? "text-[#4ec9b0]" : "text-[#f14c4c]"}>
                    {runResult.success ? "Success" : "Failed"}
                  </span>
                </p>
                <pre className="text-xs text-[#858585] font-mono overflow-auto whitespace-pre-wrap">
                  {JSON.stringify(runResult, null, 2)}
                </pre>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Create workflow modal */}
      {showCreate && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-[#252526] border border-[#3e3e42] rounded-lg p-6 w-full max-w-sm">
            <h2 className="font-semibold text-[#d4d4d4] mb-4">New workflow</h2>
            <div className="flex flex-col gap-3">
              <input placeholder="Workflow name" value={newName} onChange={(e) => setNewName(e.target.value)} className={inputCls} />
              <input placeholder="Description (optional)" value={newDesc} onChange={(e) => setNewDesc(e.target.value)} className={inputCls} />
              <div className="flex gap-2 pt-1">
                <button onClick={() => createWorkflow.mutate()} disabled={!newName || createWorkflow.isPending} className={`flex-1 ${btnPrimary}`}>Create</button>
                <button onClick={() => setShowCreate(false)} className={`flex-1 ${btnSecondary}`}>Cancel</button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Edit workflow modal */}
      {showEditWorkflow && selected && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-[#252526] border border-[#3e3e42] rounded-lg p-6 w-full max-w-sm">
            <h2 className="font-semibold text-[#d4d4d4] mb-4">Edit workflow</h2>
            <div className="flex flex-col gap-3">
              <input placeholder="Workflow name" value={editName} onChange={(e) => setEditName(e.target.value)} className={inputCls} />
              <input placeholder="Description (optional)" value={editDesc} onChange={(e) => setEditDesc(e.target.value)} className={inputCls} />
              <div className="flex gap-2 pt-1">
                <button
                  onClick={() => updateWorkflow.mutate({ name: editName, description: editDesc })}
                  disabled={!editName || updateWorkflow.isPending}
                  className={`flex-1 ${btnPrimary}`}
                >
                  Save
                </button>
                <button onClick={() => setShowEditWorkflow(false)} className={`flex-1 ${btnSecondary}`}>Cancel</button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Schedule modal */}
      {showSchedule && selected && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-[#252526] border border-[#3e3e42] rounded-lg p-6 w-full max-w-sm">
            <h2 className="font-semibold text-[#d4d4d4] mb-1">Schedule workflow</h2>
            <p className="text-xs text-[#858585] mb-4">Standard 5-field cron expression</p>
            <div className="flex flex-col gap-3">
              <div className="flex flex-col gap-1.5">
                <label className="text-xs text-[#858585] uppercase tracking-wide">Cron expression</label>
                <input
                  placeholder="0 9 * * *"
                  value={cronExpr}
                  onChange={(e) => setCronExpr(e.target.value)}
                  className={`${inputCls} font-mono`}
                />
                <p className="text-xs text-[#4e4e4e]">e.g. <span className="font-mono">0 9 * * *</span> = daily at 9am · <span className="font-mono">0 9 * * 1</span> = Mondays at 9am</p>
              </div>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={scheduleEnabled}
                  onChange={(e) => setScheduleEnabled(e.target.checked)}
                  className="accent-[#007acc]"
                />
                <span className="text-sm text-[#d4d4d4]">Enabled</span>
              </label>
              {scheduleError && <p className="text-sm text-[#f14c4c]">{scheduleError}</p>}
              <div className="flex gap-2 pt-1">
                <button onClick={() => saveSchedule.mutate()} disabled={!cronExpr || saveSchedule.isPending} className={`flex-1 ${btnPrimary}`}>
                  {saveSchedule.isPending ? "Saving..." : "Save schedule"}
                </button>
                <button onClick={() => setShowSchedule(false)} className={`flex-1 ${btnSecondary}`}>Cancel</button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Add step modal */}
      {showAddStep && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-[#252526] border border-[#3e3e42] rounded-lg p-6 w-full max-w-md">
            <h2 className="font-semibold text-[#d4d4d4] mb-4">Add step</h2>
            <div className="flex flex-col gap-3">
              <input placeholder="Step name" value={stepName} onChange={(e) => setStepName(e.target.value)} className={inputCls} />
              <div className="flex flex-col gap-1.5">
                <label className="text-xs text-[#858585] uppercase tracking-wide">Type</label>
                <select value={stepType} onChange={(e) => setStepType(e.target.value)} className={inputCls}>
                  <option value="query">Query — fetch rows from a table</option>
                  <option value="condition">Condition — filter rows by a rule</option>
                  <option value="action">Action — fire a webhook</option>
                </select>
              </div>

              {stepType === "query" && (
                <div className="flex flex-col gap-1.5">
                  <label className="text-xs text-[#858585] uppercase tracking-wide">Table</label>
                  <select value={stepTableId} onChange={(e) => setStepTableId(e.target.value)} className={inputCls}>
                    <option value="">Select a table</option>
                    {tables.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
                  </select>
                </div>
              )}

              {stepType === "condition" && (
                <div className="flex gap-2">
                  <input placeholder="Column" value={stepColumn} onChange={(e) => setStepColumn(e.target.value)} className={inputCls} />
                  <select value={stepOp} onChange={(e) => setStepOp(e.target.value)} className="bg-[#3c3c3c] border border-[#3e3e42] rounded px-2 py-2 text-sm text-[#d4d4d4] focus:outline-none focus:border-[#007acc]">
                    <option value="eq">= equals</option>
                    <option value="ne">≠ not equals</option>
                    <option value="gt">&gt; greater than</option>
                    <option value="lt">&lt; less than</option>
                  </select>
                  <input placeholder="Value" value={stepValue} onChange={(e) => setStepValue(e.target.value)} className={inputCls} />
                </div>
              )}

              {stepType === "action" && (
                <div className="flex flex-col gap-1.5">
                  <label className="text-xs text-[#858585] uppercase tracking-wide">Webhook URL</label>
                  <input placeholder="https://..." value={stepWebhook} onChange={(e) => setStepWebhook(e.target.value)} className={inputCls} />
                </div>
              )}

              {stepError && <p className="text-sm text-[#f14c4c]">{stepError}</p>}
              <div className="flex gap-2 pt-1">
                <button onClick={() => addStep.mutate()} disabled={!stepName || addStep.isPending} className={`flex-1 ${btnPrimary}`}>
                  {addStep.isPending ? "Adding..." : "Add step"}
                </button>
                <button onClick={() => setShowAddStep(false)} className={`flex-1 ${btnSecondary}`}>Cancel</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
