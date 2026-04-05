"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "@/src/api";
import { LoadingSpinner } from "@/components/LoadingSpinner";

interface TemplateStepConfig { name: string; step_type: string; config: Record<string, unknown>; order: number; }
interface Template {
  id: number; name: string; description: string;
  tags: string[]; step_configs: TemplateStepConfig[]; created_at: string;
}

const inputCls = "bg-[#3c3c3c] border border-[#3e3e42] rounded px-3 py-2 text-sm text-[#d4d4d4] focus:outline-none focus:border-[#007acc] placeholder-[#858585] w-full";
const btnPrimary = "bg-[#007acc] text-white rounded px-3 py-1.5 text-sm font-medium hover:bg-[#0069ac] disabled:opacity-50 transition-colors";
const btnSecondary = "border border-[#3e3e42] rounded px-3 py-1.5 text-sm text-[#d4d4d4] hover:bg-[#37373d] transition-colors";

export default function TemplatesPage() {
  const qc = useQueryClient();
  const [cloningTemplate, setCloningTemplate] = useState<Template | null>(null);
  const [cloneName, setCloneName] = useState("");
  const [cloneError, setCloneError] = useState("");

  const { data: templates = [], isLoading } = useQuery<Template[]>({
    queryKey: ["templates"],
    queryFn: () => api.get("/api/templates/"),
  });

  const clone = useMutation({
    mutationFn: () =>
      api.post(`/api/templates/${cloningTemplate!.id}/clone/`, { name: cloneName }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["workflows"] });
      setCloningTemplate(null);
      setCloneName("");
      setCloneError("");
    },
    onError: (e: Error) => setCloneError(e.message),
  });

  const deleteTemplate = useMutation({
    mutationFn: (id: number) => api.delete(`/api/templates/${id}/`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["templates"] }),
  });

  if (isLoading) return <LoadingSpinner />;

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-base font-semibold text-[#d4d4d4]">Templates</h1>
      </div>

      {templates.length === 0 && (
        <div className="text-sm text-[#858585]">
          <p>No templates yet.</p>
          <p className="mt-1">Go to a workflow and click <span className="text-[#d4d4d4]">Save as template</span> to create one.</p>
        </div>
      )}

      <div className="grid grid-cols-2 gap-4">
        {templates.map((t) => (
          <div key={t.id} className="border border-[#3e3e42] rounded-lg p-4 bg-[#252526]">
            <div className="flex items-start justify-between gap-2">
              <div>
                <h2 className="font-medium text-sm text-[#d4d4d4]">{t.name}</h2>
                {t.description && <p className="text-xs text-[#858585] mt-1">{t.description}</p>}
              </div>
              <button
                onClick={() => deleteTemplate.mutate(t.id)}
                className="text-xs text-[#858585] hover:text-[#f14c4c] shrink-0"
              >
                Delete
              </button>
            </div>

            <div className="flex gap-1 mt-2 flex-wrap">
              {t.tags?.map((tag) => (
                <span key={tag} className="text-xs bg-[#37373d] text-[#858585] px-2 py-0.5 rounded">{tag}</span>
              ))}
            </div>

            <p className="text-xs text-[#858585] mt-2">{t.step_configs?.length ?? 0} step{t.step_configs?.length !== 1 ? "s" : ""}</p>

            <button
              onClick={() => {
                setCloningTemplate(t);
                setCloneName(`${t.name} copy`);
                setCloneError("");
              }}
              className={`mt-3 ${btnPrimary}`}
            >
              Use template
            </button>
          </div>
        ))}
      </div>

      {/* Clone modal */}
      {cloningTemplate && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-[#252526] border border-[#3e3e42] rounded-lg p-6 w-full max-w-sm">
            <h2 className="font-semibold text-[#d4d4d4] mb-1">Use template</h2>
            <p className="text-xs text-[#858585] mb-4">Creates a new workflow from <span className="text-[#d4d4d4]">{cloningTemplate.name}</span></p>
            <div className="flex flex-col gap-3">
              <input
                placeholder="New workflow name"
                value={cloneName}
                onChange={(e) => setCloneName(e.target.value)}
                className={inputCls}
              />
              {cloneError && <p className="text-sm text-[#f14c4c]">{cloneError}</p>}
              <div className="flex gap-2 pt-1">
                <button
                  onClick={() => clone.mutate()}
                  disabled={!cloneName || clone.isPending}
                  className={`flex-1 ${btnPrimary}`}
                >
                  {clone.isPending ? "Creating..." : "Create workflow"}
                </button>
                <button onClick={() => setCloningTemplate(null)} className={`flex-1 ${btnSecondary}`}>Cancel</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
