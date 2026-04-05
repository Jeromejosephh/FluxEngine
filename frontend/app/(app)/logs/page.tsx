"use client";

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "@/src/api";
import { LoadingSpinner } from "@/components/LoadingSpinner";

interface Workflow { id: number; name: string; }
interface StepResult {
  step_name: string; step_type: string; success: boolean;
  rows_out: number; output: string; error: string;
}
interface Run {
  id: number; workflow_id: number; workflow_name: string;
  success: boolean; executed_at: string; step_count: number;
  steps: StepResult[]; error: string;
}

export default function LogsPage() {
  const [expanded, setExpanded] = useState<number | null>(null);

  const { data: workflows = [], isLoading } = useQuery<Workflow[]>({
    queryKey: ["workflows"],
    queryFn: () => api.get("/api/workflows/"),
  });

  const allRuns = useQuery<Run[]>({
    queryKey: ["allRuns", workflows.map((w) => w.id)],
    queryFn: async () => {
      const results = await Promise.all(
        workflows.map((w) => api.get<Run[]>(`/api/workflows/${w.id}/runs/`))
      );
      return results.flat().sort((a, b) =>
        new Date(b.executed_at).getTime() - new Date(a.executed_at).getTime()
      );
    },
    enabled: workflows.length > 0,
  });

  const runs = allRuns.data ?? [];

  if (isLoading || allRuns.isLoading) return <LoadingSpinner />;

  return (
    <div>
      <h1 className="text-base font-semibold text-[#d4d4d4] mb-4">Logs</h1>

      {runs.length === 0 && (
        <p className="text-sm text-[#858585]">No runs yet. Run a workflow to see logs here.</p>
      )}

      <div className="flex flex-col gap-2">
        {runs.map((run, i) => (
          <div key={i} className="border border-[#3e3e42] rounded overflow-hidden">
            <button
              className="w-full flex items-center gap-4 px-4 py-3 text-left hover:bg-[#2a2d2e] transition-colors"
              onClick={() => setExpanded(expanded === i ? null : i)}
            >
              <span className={`w-2 h-2 rounded-full shrink-0 ${run.success ? "bg-[#4ec9b0]" : "bg-[#f14c4c]"}`} />
              <span className="text-sm font-medium text-[#d4d4d4] flex-1">{run.workflow_name}</span>
              <span className="text-xs text-[#858585]">{run.step_count} step{run.step_count !== 1 ? "s" : ""}</span>
              <span className="text-xs text-[#858585]">{new Date(run.executed_at).toLocaleString()}</span>
              <span className={`text-xs font-medium ${run.success ? "text-[#4ec9b0]" : "text-[#f14c4c]"}`}>
                {run.success ? "OK" : "Failed"}
              </span>
            </button>

            {expanded === i && (
              <div className="border-t border-[#3e3e42] px-4 py-3 bg-[#2d2d2d]">
                {run.error && <p className="text-sm text-[#f14c4c] mb-3">{run.error}</p>}
                <div className="flex flex-col gap-2">
                  {run.steps?.map((step, j) => (
                    <div key={j} className="flex items-start gap-3 text-sm">
                      <span className={`mt-1 w-1.5 h-1.5 rounded-full shrink-0 ${step.success ? "bg-[#4ec9b0]" : "bg-[#f14c4c]"}`} />
                      <div>
                        <span className="font-medium text-[#d4d4d4]">{step.step_name}</span>
                        <span className="text-[#858585] ml-2 text-xs">{step.step_type}</span>
                        {step.rows_out !== undefined && (
                          <span className="text-[#858585] ml-2 text-xs">{step.rows_out} rows</span>
                        )}
                        {step.error && <p className="text-[#f14c4c] text-xs mt-0.5">{step.error}</p>}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
