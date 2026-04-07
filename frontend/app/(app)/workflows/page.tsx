"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "@/src/api";
import { LoadingSpinner } from "@/components/LoadingSpinner";
import { showToast } from "@/components/Toast";

interface Workflow {
  id: number; name: string; description: string;
  status: "draft" | "active" | "archived"; created_at: string;
}
interface Step {
  id: number; name: string; step_type: string;
  config: Record<string, unknown>; order: number; workflow_id: number;
}
interface Table { id: number; name: string; }
interface TableSchema { id: number; name: string; schema_definition: { columns: { name: string; type: string }[] }; }
interface Schedule { cron_expr: string; is_enabled: boolean; timezone: string; next_run_at: string | null; }
interface StepResult { step_id: number; step_name: string; step_type: string; success: boolean; rows_out: number; error?: string; }
interface RunResult { success: boolean; workflow_name: string; error?: string; steps: StepResult[]; }

const STATUS_COLORS: Record<string, string> = {
  draft: "bg-[#37373d] text-[#858585]",
  active: "bg-[#1e3a2f] text-[#4ec9b0]",
  archived: "bg-[#3a1e1e] text-[#f14c4c]",
};

const STEP_COLORS: Record<string, string> = {
  query: "bg-[#1e2a3a] text-[#569cd6]",
  condition: "bg-[#2a2a1e] text-[#dcdcaa]",
  action: "bg-[#2a1e3a] text-[#c586c0]",
  transform: "bg-[#2a2a1e] text-[#dcdcaa]",
};

const STEP_LABELS: Record<string, string> = {
  query: "GET",
  transform: "IF",
  condition: "IF",
  action: "THEN",
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
  const [runResult, setRunResult] = useState<RunResult | null>(null);
  const [runError, setRunError] = useState("");
  const [pendingTest, setPendingTest] = useState(false);

  // Edit workflow
  const [showEditWorkflow, setShowEditWorkflow] = useState(false);
  const [editName, setEditName] = useState("");
  const [editDesc, setEditDesc] = useState("");

  // Save as template
  const [showSaveTemplate, setShowSaveTemplate] = useState(false);
  const [templateName, setTemplateName] = useState("");
  const [templateError, setTemplateError] = useState("");

  // Schedule
  const [showSchedule, setShowSchedule] = useState(false);
  const [schedHour, setSchedHour] = useState(9);
  const [schedMinute, setSchedMinute] = useState(0);
  const [schedAmPm, setSchedAmPm] = useState<"AM" | "PM">("AM");
  const [schedDays, setSchedDays] = useState<"everyday" | number[]>("everyday");
  const [schedTimezone, setSchedTimezone] = useState(
    typeof Intl !== "undefined" ? Intl.DateTimeFormat().resolvedOptions().timeZone : "UTC"
  );
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
  const [stepTitle, setStepTitle] = useState("");
  const [stepBodyTemplate, setStepBodyTemplate] = useState("");
  const [stepEmailTo, setStepEmailTo] = useState("");
  const [stepEmailSubject, setStepEmailSubject] = useState("");
  const [stepHtmlMode, setStepHtmlMode] = useState(false);
  const [emailAccentColor, setEmailAccentColor] = useState("#007acc");
  const [emailBgColor, setEmailBgColor] = useState("#f0f4f8");
  const [emailTextColor, setEmailTextColor] = useState("#333333");
  const [emailHeaderText, setEmailHeaderText] = useState("");
  const [emailFooterText, setEmailFooterText] = useState("Sent by FluxEngine");
  const [showAddStep, setShowAddStep] = useState(false);
  const [editingStep, setEditingStep] = useState<Step | null>(null);
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

  // For column hints in email/notify step: find the query step's table
  const queryStep = steps.find((s) => s.step_type === "query");
  const queryTableId = queryStep ? (queryStep.config as Record<string, unknown>).table_id as number : null;
  const { data: queryTable } = useQuery<TableSchema>({
    queryKey: ["table-schema", queryTableId],
    queryFn: () => api.get(`/api/tables/${queryTableId}`),
    enabled: !!queryTableId,
  });
  const availableColumns = queryTable?.schema_definition?.columns?.map((c) => c.name) ?? [];

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
      showToast("Workflow created");
    },
    onError: (e: Error) => showToast(e.message, "error"),
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
      showToast("Workflow deleted");
    },
    onError: (e: Error) => showToast(e.message, "error"),
  });

  const addStep = useMutation({
    mutationFn: () => {
      let config: Record<string, unknown> = {};
      let dbStepType = stepType;
      if (stepType === "query") config = { table_id: Number(stepTableId) };
      if (stepType === "condition") config = { column: stepColumn, op: stepOp, value: stepValue };
      if (stepType === "action") config = { webhook_url: stepWebhook };
      if (stepType === "notify") { config = { subtype: "notify", webhook_url: stepWebhook, title: stepTitle, body_template: stepBodyTemplate }; dbStepType = "action"; }
      if (stepType === "email") {
        config = {
          subtype: "email", to: stepEmailTo, subject: stepEmailSubject,
          body_template: stepBodyTemplate, html_body: stepHtmlMode,
          ...(stepHtmlMode && { style: {
            accent_color: emailAccentColor, bg_color: emailBgColor, text_color: emailTextColor,
            header_text: emailHeaderText, footer_text: emailFooterText,
          }}),
        };
        dbStepType = "action";
      }
      if (stepType === "transform") config = { select_columns: [] };
      return api.post(`/api/workflows/${selected!.id}/steps/`, {
        name: stepName, step_type: dbStepType,
        workflow_id: selected!.id, config, order: steps.length,
      });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["steps", selected?.id] });
      setShowAddStep(false); setStepName(""); setStepType("query");
      setStepTableId(""); setStepColumn(""); setStepOp("eq");
      setStepValue(""); setStepWebhook(""); setStepTitle(""); setStepBodyTemplate("");
      setStepEmailTo(""); setStepEmailSubject(""); setStepHtmlMode(false);
      setEmailAccentColor("#007acc"); setEmailBgColor("#f0f4f8"); setEmailTextColor("#333333");
      setEmailHeaderText(""); setEmailFooterText("Sent by FluxEngine"); setStepError("");
      setPendingTest(true);
      showToast("Step added");
    },
    onError: (e: Error) => setStepError(e.message),
  });

  const deleteStep = useMutation({
    mutationFn: (stepId: number) => api.delete(`/api/workflows/${selected!.id}/steps/${stepId}/`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["steps", selected?.id] });
      setPendingTest(true);
      showToast("Step deleted");
    },
    onError: (e: Error) => showToast(e.message, "error"),
  });

  const updateStep = useMutation({
    mutationFn: () => {
      let config: Record<string, unknown> = {};
      let dbStepType = stepType;
      if (stepType === "query") config = { table_id: Number(stepTableId) };
      if (stepType === "condition") config = { column: stepColumn, op: stepOp, value: stepValue };
      if (stepType === "action") config = { webhook_url: stepWebhook };
      if (stepType === "notify") { config = { subtype: "notify", webhook_url: stepWebhook, title: stepTitle, body_template: stepBodyTemplate }; dbStepType = "action"; }
      if (stepType === "email") {
        config = {
          subtype: "email", to: stepEmailTo, subject: stepEmailSubject,
          body_template: stepBodyTemplate, html_body: stepHtmlMode,
          ...(stepHtmlMode && { style: {
            accent_color: emailAccentColor, bg_color: emailBgColor, text_color: emailTextColor,
            header_text: emailHeaderText, footer_text: emailFooterText,
          }}),
        };
        dbStepType = "action";
      }
      if (stepType === "transform") config = { select_columns: [] };
      return api.put(`/api/workflows/${selected!.id}/steps/${editingStep!.id}/`, { name: stepName, step_type: dbStepType, config });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["steps", selected?.id] });
      setEditingStep(null); setStepName(""); setStepType("query");
      setStepTableId(""); setStepColumn(""); setStepOp("eq");
      setStepValue(""); setStepWebhook(""); setStepTitle(""); setStepBodyTemplate("");
      setStepEmailTo(""); setStepEmailSubject(""); setStepHtmlMode(false);
      setEmailAccentColor("#007acc"); setEmailBgColor("#f0f4f8"); setEmailTextColor("#333333");
      setEmailHeaderText(""); setEmailFooterText("Sent by FluxEngine"); setStepError("");
      setPendingTest(true);
      showToast("Step updated");
    },
    onError: (e: Error) => setStepError(e.message),
  });

  function openEditStep(step: Step) {
    const cfg = step.config as Record<string, unknown>;
    const sub = cfg.subtype as string | undefined;
    // determine UI stepType
    let uiType = step.step_type;
    if (step.step_type === "action") uiType = sub === "email" ? "email" : sub === "notify" ? "notify" : "action";
    setStepType(uiType);
    setStepName(step.name);
    if (uiType === "query") setStepTableId(String(cfg.table_id ?? ""));
    if (uiType === "condition") { setStepColumn(String(cfg.column ?? "")); setStepOp(String(cfg.op ?? "eq")); setStepValue(String(cfg.value ?? "")); }
    if (uiType === "action") setStepWebhook(String(cfg.webhook_url ?? ""));
    if (uiType === "notify") { setStepWebhook(String(cfg.webhook_url ?? "")); setStepTitle(String(cfg.title ?? "")); setStepBodyTemplate(String(cfg.body_template ?? "")); }
    if (uiType === "email") {
      setStepEmailTo(String(cfg.to ?? ""));
      setStepEmailSubject(String(cfg.subject ?? ""));
      setStepBodyTemplate(String(cfg.body_template ?? ""));
      setStepHtmlMode(!!cfg.html_body);
      const s = cfg.style as Record<string, string> | undefined;
      if (s) {
        setEmailAccentColor(s.accent_color ?? "#007acc");
        setEmailBgColor(s.bg_color ?? "#f0f4f8");
        setEmailTextColor(s.text_color ?? "#333333");
        setEmailHeaderText(s.header_text ?? "");
        setEmailFooterText(s.footer_text ?? "Sent by FluxEngine");
      }
    }
    setStepError("");
    setEditingStep(step);
  }

  const saveAsTemplate = useMutation({
    mutationFn: () =>
      api.post("/api/templates/", {
        name: templateName,
        description: selected!.description,
        tags: [],
        step_configs: steps.map((s) => ({
          name: s.name, step_type: s.step_type, config: s.config, order: s.order,
        })),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["templates"] });
      setShowSaveTemplate(false);
      setTemplateName("");
      setTemplateError("");
    },
    onError: (e: Error) => setTemplateError(e.message),
  });

  const runWorkflow = useMutation({
    mutationFn: () => api.post<RunResult>(`/api/workflows/${selected!.id}/run/`, {}),
    onMutate: () => setPendingTest(false),
    onSuccess: (res) => { setRunResult(res); setRunError(""); },
    onError: (e: Error) => setRunError(e.message),
  });

  function buildCron(): string {
    const h24 = schedAmPm === "AM"
      ? (schedHour === 12 ? 0 : schedHour)
      : (schedHour === 12 ? 12 : schedHour + 12);
    const dayField = schedDays === "everyday" ? "*" : (schedDays as number[]).join(",");
    return `${schedMinute} ${h24} * * ${dayField}`;
  }

  function describeSchedule(cron: string, tz: string): string {
    const parts = cron.split(" ");
    if (parts.length !== 5) return cron;
    const [min, hr, , , dow] = parts;
    const h = parseInt(hr);
    const ampm = h < 12 ? "AM" : "PM";
    const h12 = h === 0 ? 12 : h > 12 ? h - 12 : h;
    const minStr = parseInt(min) === 0 ? "" : `:${min.padStart(2, "0")}`;
    const dayNames = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const dayStr = dow === "*" ? "every day" : dow.split(",").map((d) => dayNames[parseInt(d)] ?? d).join(", ");
    const tzLabel = tz.split("/").pop()?.replace(/_/g, " ") ?? tz;
    return `${h12}${minStr} ${ampm} - ${dayStr} - ${tzLabel}`;
  }

  function buildEmailPreview(body: string, accent: string, bg: string, text: string, header: string, footer: string): string {
    const headerBlock = header
      ? `<tr><td style="background:${accent};padding:18px 24px;border-radius:6px 6px 0 0;"><p style="margin:0;color:#ffffff;font-size:15px;font-weight:600;">${header}</p></td></tr>`
      : "";
    const footerBlock = footer
      ? `<tr><td style="padding:12px 24px;background:#f9f9f9;color:#888888;font-size:11px;border-top:1px solid #eeeeee;border-radius:0 0 6px 6px;">${footer}</td></tr>`
      : "";
    const bodyHtml = body
      ? body.replace(/\{(\w+)\}/g, (_, k) => `<span style="background:#e8f4fd;color:${accent};padding:1px 4px;border-radius:3px;font-size:11px;">{${k}}</span>`).replace(/\n/g, "<br>")
      : `<span style="color:#aaaaaa;">Your message will appear here…</span>`;
    return `<html><body style="margin:0;padding:16px;background:${bg};font-family:-apple-system,Arial,sans-serif;"><table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center"><table width="100%" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:6px;box-shadow:0 2px 8px rgba(0,0,0,0.1);">${headerBlock}<tr><td style="padding:24px;color:${text};font-size:13px;line-height:1.6;">${bodyHtml}</td></tr>${footerBlock}</table></td></tr></table></body></html>`;
  }

  function openScheduleModal() {
    if (schedule) {
      // parse existing cron back to UI state
      const parts = schedule.cron_expr.split(" ");
      if (parts.length === 5) {
        const h = parseInt(parts[1]);
        setSchedAmPm(h < 12 ? "AM" : "PM");
        setSchedHour(h === 0 ? 12 : h > 12 ? h - 12 : h);
        setSchedMinute(parseInt(parts[0]));
        setSchedDays(parts[4] === "*" ? "everyday" : parts[4].split(",").map(Number));
      }
      setSchedTimezone(schedule.timezone || "UTC");
      setScheduleEnabled(schedule.is_enabled);
    }
    setScheduleError("");
    setShowSchedule(true);
  }

  const saveSchedule = useMutation({
    mutationFn: () =>
      api.post(`/api/workflows/${selected!.id}/schedule/`, {
        cron_expr: buildCron(),
        is_enabled: scheduleEnabled,
        timezone: schedTimezone,
      }),
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
              onClick={() => { setSelected(w); setRunResult(null); setRunError(""); setPendingTest(false); }}
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
                {steps.length > 0 && (
                  <button
                    onClick={() => {
                      setTemplateName(selected.name);
                      setTemplateError("");
                      setShowSaveTemplate(true);
                    }}
                    className={btnSecondary}
                  >
                    Save as template
                  </button>
                )}
                <button
                  onClick={openScheduleModal}
                  className={btnSecondary}
                >
                  Schedule
                </button>
                {selected.status === "draft" && (
                  <button onClick={() => updateWorkflow.mutate({ status: "active" })} className={btnSecondary}>
                    Activate
                  </button>
                )}
                <button
                  onClick={() => { setRunResult(null); setRunError(""); runWorkflow.mutate(); }}
                  disabled={runWorkflow.isPending}
                  className={`bg-[#1e3a2f] text-[#4ec9b0] rounded px-3 py-1.5 text-sm font-medium hover:bg-[#2a5a3f] disabled:opacity-50 transition-colors border ${
                    pendingTest ? "border-[#4ec9b0] ring-2 ring-[#4ec9b0] ring-offset-1 ring-offset-[#1e1e1e] animate-pulse" : "border-[#2a5a3f]"
                  }`}
                >
                  {runWorkflow.isPending ? "Running..." : selected.status === "active" ? "▶ Run now" : "▶ Run test"}
                </button>
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
                  {schedule.is_enabled ? describeSchedule(schedule.cron_expr, schedule.timezone) : "Schedule disabled"}
                  {schedule.next_run_at && schedule.is_enabled && (
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
                        {STEP_LABELS[step.step_type] ?? step.step_type.toUpperCase()}
                      </span>
                      <span className="text-sm text-[#d4d4d4] font-medium flex-1">{step.name}</span>
                      <button onClick={() => openEditStep(step)} className="text-xs text-[#858585] hover:text-[#007acc]">Edit</button>
                      <button onClick={() => deleteStep.mutate(step.id)} className="text-xs text-[#858585] hover:text-[#f14c4c]">Delete</button>
                    </div>
                    <p className="text-xs text-[#4e4e4e] mt-1 ml-6 font-mono">
                      {JSON.stringify(step.config)}
                    </p>
                  </div>
                ))}
                {steps.length === 0 && (
                  <p className="text-sm text-[#858585]">No steps yet - add one to get started</p>
                )}
              </div>
            </div>

            {/* Run result */}
            {runError && <p className="text-sm text-[#f14c4c] mb-3">{runError}</p>}
            {runResult && (
              <div className="border border-[#3e3e42] rounded-lg p-4 bg-[#252526]">
                <div className="flex items-center gap-2 mb-3">
                  <span className={`w-2 h-2 rounded-full ${runResult.success ? "bg-[#4ec9b0]" : "bg-[#f14c4c]"}`} />
                  <p className="text-sm font-medium text-[#d4d4d4]">
                    {runResult.success ? "Run complete" : "Run failed"}
                  </p>
                  {runResult.error && <p className="text-xs text-[#f14c4c] ml-1">{runResult.error}</p>}
                </div>
                <div className="flex flex-col gap-2">
                  {runResult.steps.map((s, i) => (
                    <div key={s.step_id} className="flex items-center gap-3 text-xs">
                      <span className="text-[#4e4e4e] w-4 shrink-0">{i + 1}</span>
                      <span className={`px-2 py-0.5 rounded font-medium shrink-0 ${STEP_COLORS[s.step_type] ?? STEP_COLORS.transform}`}>
                        {STEP_LABELS[s.step_type] ?? s.step_type.toUpperCase()}
                      </span>
                      <span className="text-[#d4d4d4] flex-1">{s.step_name}</span>
                      {s.success ? (
                        <span className="text-[#858585]">{s.rows_out} row{s.rows_out !== 1 ? "s" : ""}</span>
                      ) : (
                        <span className="text-[#f14c4c] truncate max-w-50">{s.error}</span>
                      )}
                    </div>
                  ))}
                </div>
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
            <p className="text-xs text-[#858585] mb-4">Runs automatically at the time you set.</p>
            <div className="flex flex-col gap-4">

              {/* Time row */}
              <div>
                <label className="block text-xs text-[#858585] mb-1.5">Time</label>
                <div className="flex gap-2 items-center">
                  <select value={schedHour} onChange={(e) => setSchedHour(Number(e.target.value))}
                    className="bg-[#3c3c3c] border border-[#3e3e42] rounded px-2 py-2 text-sm text-[#d4d4d4] focus:outline-none focus:border-[#007acc]">
                    {[12,1,2,3,4,5,6,7,8,9,10,11].map((h) => (
                      <option key={h} value={h}>{h}</option>
                    ))}
                  </select>
                  <span className="text-[#858585] text-sm">:</span>
                  <select value={schedMinute} onChange={(e) => setSchedMinute(Number(e.target.value))}
                    className="bg-[#3c3c3c] border border-[#3e3e42] rounded px-2 py-2 text-sm text-[#d4d4d4] focus:outline-none focus:border-[#007acc]">
                    {[0,15,30,45].map((m) => (
                      <option key={m} value={m}>{String(m).padStart(2, "0")}</option>
                    ))}
                  </select>
                  <select value={schedAmPm} onChange={(e) => setSchedAmPm(e.target.value as "AM" | "PM")}
                    className="bg-[#3c3c3c] border border-[#3e3e42] rounded px-2 py-2 text-sm text-[#d4d4d4] focus:outline-none focus:border-[#007acc]">
                    <option value="AM">AM</option>
                    <option value="PM">PM</option>
                  </select>
                </div>
              </div>

              {/* Days row */}
              <div>
                <label className="block text-xs text-[#858585] mb-1.5">Days</label>
                <div className="flex gap-1.5 flex-wrap">
                  {["Every day", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"].map((label, i) => {
                    const isEvery = label === "Every day";
                    const dayNum = i; // 0=Every day offset, 1=Mon(1), 2=Tue(2) ... 7=Sun(0)
                    const cronDay = i === 7 ? 0 : i; // Sun=0
                    const isActive = isEvery
                      ? schedDays === "everyday"
                      : Array.isArray(schedDays) && schedDays.includes(cronDay);
                    return (
                      <button
                        key={label}
                        type="button"
                        onClick={() => {
                          if (isEvery) { setSchedDays("everyday"); return; }
                          if (schedDays === "everyday") { setSchedDays([cronDay]); return; }
                          const arr = schedDays as number[];
                          setSchedDays(arr.includes(cronDay)
                            ? arr.filter((d) => d !== cronDay).length === 0 ? "everyday" : arr.filter((d) => d !== cronDay)
                            : [...arr, cronDay].sort());
                        }}
                        className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                          isActive ? "bg-[#007acc] text-white" : "bg-[#3c3c3c] text-[#858585] hover:text-[#d4d4d4]"
                        }`}
                      >
                        {label}
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Timezone */}
              <div>
                <label className="block text-xs text-[#858585] mb-1.5">Timezone</label>
                <select value={schedTimezone} onChange={(e) => setSchedTimezone(e.target.value)}
                  className="bg-[#3c3c3c] border border-[#3e3e42] rounded px-2 py-2 text-sm text-[#d4d4d4] focus:outline-none focus:border-[#007acc] w-full">
                  {[
                    ["Pacific/Auckland", "New Zealand (Auckland)"],
                    ["Pacific/Chatham", "New Zealand (Chatham Islands)"],
                    ["Australia/Sydney", "Australia (Sydney)"],
                    ["Australia/Melbourne", "Australia (Melbourne)"],
                    ["Australia/Brisbane", "Australia (Brisbane)"],
                    ["Australia/Adelaide", "Australia (Adelaide)"],
                    ["Australia/Perth", "Australia (Perth)"],
                    ["Asia/Tokyo", "Japan (Tokyo)"],
                    ["Asia/Seoul", "South Korea (Seoul)"],
                    ["Asia/Shanghai", "China (Shanghai)"],
                    ["Asia/Singapore", "Singapore"],
                    ["Asia/Bangkok", "Thailand (Bangkok)"],
                    ["Asia/Kolkata", "India (Kolkata)"],
                    ["Asia/Dubai", "UAE (Dubai)"],
                    ["Europe/London", "UK (London)"],
                    ["Europe/Paris", "France (Paris)"],
                    ["Europe/Berlin", "Germany (Berlin)"],
                    ["Europe/Moscow", "Russia (Moscow)"],
                    ["Africa/Johannesburg", "South Africa (Johannesburg)"],
                    ["America/New_York", "US Eastern (New York)"],
                    ["America/Chicago", "US Central (Chicago)"],
                    ["America/Denver", "US Mountain (Denver)"],
                    ["America/Los_Angeles", "US Pacific (Los Angeles)"],
                    ["America/Toronto", "Canada (Toronto)"],
                    ["America/Vancouver", "Canada (Vancouver)"],
                    ["America/Sao_Paulo", "Brazil (Sao Paulo)"],
                    ["UTC", "UTC"],
                  ].map(([value, label]) => (
                    <option key={value} value={value}>{label}</option>
                  ))}
                </select>
              </div>

              {/* Enabled toggle */}
              <label className="flex items-center gap-2 cursor-pointer">
                <input type="checkbox" checked={scheduleEnabled}
                  onChange={(e) => setScheduleEnabled(e.target.checked)}
                  className="accent-[#007acc]" />
                <span className="text-sm text-[#d4d4d4]">Enabled</span>
              </label>

              {scheduleError && <p className="text-sm text-[#f14c4c]">{scheduleError}</p>}
              <div className="flex gap-2 pt-1">
                <button onClick={() => saveSchedule.mutate()} disabled={saveSchedule.isPending} className={`flex-1 ${btnPrimary}`}>
                  {saveSchedule.isPending ? "Saving..." : "Save schedule"}
                </button>
                <button onClick={() => setShowSchedule(false)} className={`flex-1 ${btnSecondary}`}>Cancel</button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Save as template modal */}
      {showSaveTemplate && selected && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-[#252526] border border-[#3e3e42] rounded-lg p-6 w-full max-w-sm">
            <h2 className="font-semibold text-[#d4d4d4] mb-1">Save as template</h2>
            <p className="text-xs text-[#858585] mb-4">Saves this workflow's steps as a reusable template</p>
            <div className="flex flex-col gap-3">
              <input
                placeholder="Template name"
                value={templateName}
                onChange={(e) => setTemplateName(e.target.value)}
                className={inputCls}
              />
              {templateError && <p className="text-sm text-[#f14c4c]">{templateError}</p>}
              <div className="flex gap-2 pt-1">
                <button
                  onClick={() => saveAsTemplate.mutate()}
                  disabled={!templateName || saveAsTemplate.isPending}
                  className={`flex-1 ${btnPrimary}`}
                >
                  {saveAsTemplate.isPending ? "Saving..." : "Save template"}
                </button>
                <button onClick={() => setShowSaveTemplate(false)} className={`flex-1 ${btnSecondary}`}>Cancel</button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Add / Edit step modal */}
      {(showAddStep || editingStep) && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-[#252526] border border-[#3e3e42] rounded-lg p-6 w-full max-w-md">
            <h2 className="font-semibold text-[#d4d4d4] mb-4">{editingStep ? "Edit step" : "Add step"}</h2>
            <div className="flex flex-col gap-3">
              <input placeholder="Step name" value={stepName} onChange={(e) => setStepName(e.target.value)} className={inputCls} />
              {!editingStep && (
                <div className="flex flex-col gap-1.5">
                  <label className="text-xs text-[#858585] uppercase tracking-wide">Type</label>
                  <select value={stepType} onChange={(e) => setStepType(e.target.value)} className={inputCls}>
                    <option value="query">GET - fetch rows from a table</option>
                    <option value="condition">IF - filter rows by a rule</option>
                    <option value="action">THEN - send raw JSON to a webhook</option>
                    <option value="notify">THEN - send formatted message (ntfy, Slack, etc.)</option>
                    <option value="email">THEN - send formatted email</option>
                  </select>
                </div>
              )}

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
                    <option value="contains">contains</option>
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

              {stepType === "email" && (
                <div className="flex flex-col gap-3">
                  <div className="flex flex-col gap-1.5">
                    <label className="text-xs text-[#858585] uppercase tracking-wide">To</label>
                    <input placeholder="recipient@email.com" value={stepEmailTo} onChange={(e) => setStepEmailTo(e.target.value)} className={inputCls} />
                  </div>
                  <div className="flex flex-col gap-1.5">
                    <label className="text-xs text-[#858585] uppercase tracking-wide">Subject</label>
                    <input placeholder="e.g. Follow-up Reminder" value={stepEmailSubject} onChange={(e) => setStepEmailSubject(e.target.value)} className={inputCls} />
                  </div>
                  <div className="flex flex-col gap-1.5">
                    <div className="flex items-center justify-between">
                      <label className="text-xs text-[#858585] uppercase tracking-wide">Body</label>
                      <label className="flex items-center gap-1.5 cursor-pointer">
                        <input type="checkbox" checked={stepHtmlMode} onChange={(e) => setStepHtmlMode(e.target.checked)} className="accent-[#007acc]" />
                        <span className="text-xs text-[#858585]">Styled email</span>
                      </label>
                    </div>
                    {availableColumns.length > 0 && (
                      <div className="flex gap-1 flex-wrap mt-1">
                        {availableColumns.map((col) => (
                          <button key={col} type="button"
                            onClick={() => setStepBodyTemplate((prev) => prev + `{${col}}`)}
                            className="text-xs bg-[#37373d] text-[#4ec9b0] px-2 py-0.5 rounded hover:bg-[#3e3e42] font-mono">
                            +{"{" + col + "}"}
                          </button>
                        ))}
                      </div>
                    )}
                    <textarea
                      rows={4}
                      placeholder={"Hi,\n\nYou have a follow-up with {company} due on {follow_up_date}.\n\nRole: {role}"}
                      value={stepBodyTemplate}
                      onChange={(e) => setStepBodyTemplate(e.target.value)}
                      className={`${inputCls} resize-y text-xs mt-1`}
                    />
                    <p className="text-xs text-[#4e4e4e]">Use {"{column}"} to insert values. Each matching row is sent as a section.</p>
                  </div>

                  {/* Design panel */}
                  {stepHtmlMode && (
                    <div className="border border-[#3e3e42] rounded-lg p-3 flex flex-col gap-3 bg-[#1e1e1e]">
                      <p className="text-xs font-medium text-[#d4d4d4]">Design</p>

                      {/* Colors */}
                      <div className="flex gap-3">
                        <div className="flex flex-col gap-1 flex-1">
                          <label className="text-xs text-[#858585]">Accent</label>
                          <div className="flex gap-1.5 items-center">
                            <input type="color" value={emailAccentColor} onChange={(e) => setEmailAccentColor(e.target.value)}
                              className="w-8 h-8 rounded cursor-pointer border border-[#3e3e42] bg-transparent p-0.5" />
                            <span className="text-xs text-[#858585] font-mono">{emailAccentColor}</span>
                          </div>
                        </div>
                        <div className="flex flex-col gap-1 flex-1">
                          <label className="text-xs text-[#858585]">Background</label>
                          <div className="flex gap-1.5 items-center">
                            <input type="color" value={emailBgColor} onChange={(e) => setEmailBgColor(e.target.value)}
                              className="w-8 h-8 rounded cursor-pointer border border-[#3e3e42] bg-transparent p-0.5" />
                            <span className="text-xs text-[#858585] font-mono">{emailBgColor}</span>
                          </div>
                        </div>
                        <div className="flex flex-col gap-1 flex-1">
                          <label className="text-xs text-[#858585]">Text</label>
                          <div className="flex gap-1.5 items-center">
                            <input type="color" value={emailTextColor} onChange={(e) => setEmailTextColor(e.target.value)}
                              className="w-8 h-8 rounded cursor-pointer border border-[#3e3e42] bg-transparent p-0.5" />
                            <span className="text-xs text-[#858585] font-mono">{emailTextColor}</span>
                          </div>
                        </div>
                      </div>

                      {/* Header / Footer text */}
                      <div className="flex flex-col gap-1.5">
                        <label className="text-xs text-[#858585]">Header title</label>
                        <input placeholder="e.g. Daily Follow-up Reminder" value={emailHeaderText}
                          onChange={(e) => setEmailHeaderText(e.target.value)} className={inputCls} />
                      </div>
                      <div className="flex flex-col gap-1.5">
                        <label className="text-xs text-[#858585]">Footer text</label>
                        <input placeholder="e.g. Sent by FluxEngine" value={emailFooterText}
                          onChange={(e) => setEmailFooterText(e.target.value)} className={inputCls} />
                      </div>

                      {/* Live preview */}
                      <div>
                        <p className="text-xs text-[#858585] mb-1.5">Preview</p>
                        <iframe
                          srcDoc={buildEmailPreview(stepBodyTemplate, emailAccentColor, emailBgColor, emailTextColor, emailHeaderText, emailFooterText)}
                          className="w-full rounded border border-[#3e3e42]"
                          style={{ height: 240 }}
                          sandbox="allow-same-origin"
                        />
                      </div>
                    </div>
                  )}
                </div>
              )}

              {stepType === "notify" && (
                <div className="flex flex-col gap-3">
                  <div className="flex flex-col gap-1.5">
                    <label className="text-xs text-[#858585] uppercase tracking-wide">Webhook URL</label>
                    <input placeholder="https://ntfy.sh/your-topic" value={stepWebhook} onChange={(e) => setStepWebhook(e.target.value)} className={inputCls} />
                  </div>
                  <div className="flex flex-col gap-1.5">
                    <label className="text-xs text-[#858585] uppercase tracking-wide">Notification title</label>
                    <input placeholder="e.g. Follow-up Reminder" value={stepTitle} onChange={(e) => setStepTitle(e.target.value)} className={inputCls} />
                  </div>
                  <div className="flex flex-col gap-1.5">
                    <label className="text-xs text-[#858585] uppercase tracking-wide">Message template</label>
                    <input
                      placeholder="e.g. {company} | {role} | Due: {follow_up_date}"
                      value={stepBodyTemplate}
                      onChange={(e) => setStepBodyTemplate(e.target.value)}
                      className={inputCls}
                    />
                    <p className="text-xs text-[#4e4e4e]">Use {"{"} column_name {"}"} to insert values from each row</p>
                  </div>
                </div>
              )}

              {stepError && <p className="text-sm text-[#f14c4c]">{stepError}</p>}
              <div className="flex gap-2 pt-1">
                {editingStep ? (
                  <button onClick={() => updateStep.mutate()} disabled={!stepName || updateStep.isPending} className={`flex-1 ${btnPrimary}`}>
                    {updateStep.isPending ? "Saving..." : "Save changes"}
                  </button>
                ) : (
                  <button onClick={() => addStep.mutate()} disabled={!stepName || addStep.isPending} className={`flex-1 ${btnPrimary}`}>
                    {addStep.isPending ? "Adding..." : "Add step"}
                  </button>
                )}
                <button onClick={() => { setShowAddStep(false); setEditingStep(null); setStepError(""); }} className={`flex-1 ${btnSecondary}`}>Cancel</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
