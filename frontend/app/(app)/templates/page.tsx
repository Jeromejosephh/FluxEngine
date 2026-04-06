"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/src/api";
import { LoadingSpinner } from "@/components/LoadingSpinner";

const FORM_BASE = "https://fluxengine-production.up.railway.app";

interface CatalogInput { key: string; label: string; type: string; placeholder: string; }
interface CatalogTemplate { id: string; name: string; description: string; icon: string; inputs: CatalogInput[]; }
interface SavedTemplate { id: number; name: string; description: string; tags: string[]; step_configs: unknown[]; }
interface ActivateResult { workflow_id: number; workflow_name: string; tables: { id: number; name: string; form_token: string }[]; }

const inputCls = "bg-[#3c3c3c] border border-[#3e3e42] rounded px-3 py-2 text-sm text-[#d4d4d4] focus:outline-none focus:border-[#007acc] placeholder-[#858585] w-full";
const btnPrimary = "bg-[#007acc] text-white rounded px-3 py-1.5 text-sm font-medium hover:bg-[#0069ac] disabled:opacity-50 transition-colors";
const btnSecondary = "border border-[#3e3e42] rounded px-3 py-1.5 text-sm text-[#d4d4d4] hover:bg-[#37373d] transition-colors";

export default function TemplatesPage() {
  const qc = useQueryClient();
  const router = useRouter();

  // Catalog activation
  const [activating, setActivating] = useState<CatalogTemplate | null>(null);
  const [inputValues, setInputValues] = useState<Record<string, string>>({});
  const [activateError, setActivateError] = useState("");
  const [activated, setActivated] = useState<ActivateResult | null>(null);
  const [copied, setCopied] = useState(false);

  // Saved template cloning
  const [cloningTemplate, setCloningTemplate] = useState<SavedTemplate | null>(null);
  const [cloneName, setCloneName] = useState("");
  const [cloneError, setCloneError] = useState("");

  const { data: catalog = [], isLoading: catalogLoading } = useQuery<CatalogTemplate[]>({
    queryKey: ["catalog"],
    queryFn: () => api.get("/api/templates/catalog"),
  });

  const { data: saved = [], isLoading: savedLoading } = useQuery<SavedTemplate[]>({
    queryKey: ["templates"],
    queryFn: () => api.get("/api/templates/"),
  });

  const activate = useMutation({
    mutationFn: () =>
      api.post<ActivateResult>(`/api/templates/catalog/${activating!.id}/activate`, { inputs: inputValues }),
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ["workflows"] });
      qc.invalidateQueries({ queryKey: ["tables"] });
      setActivating(null);
      setInputValues({});
      setActivateError("");
      setActivated(result);
    },
    onError: (e: Error) => setActivateError(e.message),
  });

  const clone = useMutation({
    mutationFn: () =>
      api.post(`/api/templates/${cloningTemplate!.id}/clone/`, { name: cloneName }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["workflows"] });
      setCloningTemplate(null);
      setCloneName("");
      setCloneError("");
      router.push("/workflows");
    },
    onError: (e: Error) => setCloneError(e.message),
  });

  const deleteTemplate = useMutation({
    mutationFn: (id: number) => api.delete(`/api/templates/${id}/`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["templates"] }),
  });

  const openActivate = (t: CatalogTemplate) => {
    setActivating(t);
    setInputValues(Object.fromEntries(t.inputs.map((i) => [i.key, ""])));
    setActivateError("");
  };

  if (catalogLoading || savedLoading) return <LoadingSpinner />;

  const allInputsFilled = activating?.inputs.every((i) => inputValues[i.key]?.trim());

  return (
    <div className="space-y-8">
      {/* Catalog section */}
      <div>
        <h1 className="text-base font-semibold text-[#d4d4d4] mb-1">Templates</h1>
        <p className="text-xs text-[#858585] mb-4">Pick a template and you&apos;re ready to go — tables, workflow, and steps are all created automatically.</p>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {catalog.map((t) => (
            <div key={t.id} className="border border-[#3e3e42] rounded-lg p-5 bg-[#252526] flex flex-col gap-3">
              <div className="text-2xl">{t.icon}</div>
              <div>
                <h2 className="font-semibold text-sm text-[#d4d4d4]">{t.name}</h2>
                <p className="text-xs text-[#858585] mt-1">{t.description}</p>
              </div>
              <button onClick={() => openActivate(t)} className={`mt-auto ${btnPrimary}`}>
                Use template
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Saved templates section */}
      {saved.length > 0 && (
        <div>
          <h2 className="text-sm font-semibold text-[#d4d4d4] mb-3">My Templates</h2>
          <div className="grid grid-cols-2 gap-4">
            {saved.map((t) => (
              <div key={t.id} className="border border-[#3e3e42] rounded-lg p-4 bg-[#252526]">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <h3 className="font-medium text-sm text-[#d4d4d4]">{t.name}</h3>
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
                <p className="text-xs text-[#858585] mt-2">
                  {Array.isArray(t.step_configs) ? t.step_configs.length : 0} step{Array.isArray(t.step_configs) && t.step_configs.length !== 1 ? "s" : ""}
                </p>
                <button
                  onClick={() => { setCloningTemplate(t); setCloneName(`${t.name} copy`); setCloneError(""); }}
                  className={`mt-3 ${btnPrimary}`}
                >
                  Use template
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Activate catalog modal */}
      {activating && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-[#252526] border border-[#3e3e42] rounded-lg p-6 w-full max-w-sm">
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xl">{activating.icon}</span>
              <h2 className="font-semibold text-[#d4d4d4]">{activating.name}</h2>
            </div>
            <p className="text-xs text-[#858585] mb-4">{activating.description}</p>
            <div className="flex flex-col gap-3">
              {activating.inputs.map((inp) => (
                <div key={inp.key}>
                  <label className="block text-xs text-[#858585] mb-1">{inp.label}</label>
                  <input
                    type={inp.type}
                    placeholder={inp.placeholder}
                    value={inputValues[inp.key] ?? ""}
                    onChange={(e) => setInputValues((prev) => ({ ...prev, [inp.key]: e.target.value }))}
                    className={inputCls}
                  />
                </div>
              ))}
              {activateError && <p className="text-sm text-[#f14c4c]">{activateError}</p>}
              <div className="flex gap-2 pt-1">
                <button
                  onClick={() => activate.mutate()}
                  disabled={!allInputsFilled || activate.isPending}
                  className={`flex-1 ${btnPrimary}`}
                >
                  {activate.isPending ? "Setting up..." : "Set up"}
                </button>
                <button onClick={() => setActivating(null)} className={`flex-1 ${btnSecondary}`}>Cancel</button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Success screen after activation */}
      {activated && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-[#252526] border border-[#3e3e42] rounded-lg p-6 w-full max-w-md">
            <div className="text-2xl mb-2">✓</div>
            <h2 className="font-semibold text-[#d4d4d4] mb-1">{activated.workflow_name} is ready</h2>
            <p className="text-xs text-[#858585] mb-5">Runs automatically every day at 9am. Add data and it will email you.</p>

            {activated.tables.map((t) => {
              const formUrl = `${FORM_BASE}/form/${t.form_token}`;
              return (
                <div key={t.id} className="mb-4">
                  <p className="text-xs text-[#858585] mb-1">Shareable form link for <span className="text-[#d4d4d4]">{t.name}</span></p>
                  <div className="flex gap-2">
                    <input readOnly value={formUrl} className="bg-[#3c3c3c] border border-[#3e3e42] rounded px-3 py-1.5 text-xs text-[#d4d4d4] flex-1 min-w-0" />
                    <button
                      onClick={() => { navigator.clipboard.writeText(formUrl); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
                      className={btnSecondary + " shrink-0 text-xs"}
                    >
                      {copied ? "Copied!" : "Copy"}
                    </button>
                  </div>
                  <p className="text-xs text-[#858585] mt-1">Share this link — anyone can fill in the form without logging in.</p>
                </div>
              );
            })}

            <div className="flex gap-2 mt-4">
              <button onClick={() => { setActivated(null); router.push("/workflows"); }} className={`flex-1 ${btnPrimary}`}>
                Go to workflow
              </button>
              <button onClick={() => { setActivated(null); router.push("/tables"); }} className={`flex-1 ${btnSecondary}`}>
                View table
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Clone saved template modal */}
      {cloningTemplate && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-[#252526] border border-[#3e3e42] rounded-lg p-6 w-full max-w-sm">
            <h2 className="font-semibold text-[#d4d4d4] mb-1">Use template</h2>
            <p className="text-xs text-[#858585] mb-4">Creates a new workflow from <span className="text-[#d4d4d4]">{cloningTemplate.name}</span></p>
            <div className="flex flex-col gap-3">
              <input
                placeholder="Workflow name"
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
