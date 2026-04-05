"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { LoadingSpinner } from "@/components/LoadingSpinner";

interface Template {
  id: number; name: string; description: string;
  tags: string[]; created_at: string;
}

export default function TemplatesPage() {
  const qc = useQueryClient();

  const { data: templates = [], isLoading } = useQuery<Template[]>({
    queryKey: ["templates"],
    queryFn: () => api.get("/api/templates"),
  });

  const clone = useMutation({
    mutationFn: (id: number) =>
      api.post(`/api/templates/${id}/clone`, { name: `Clone of template ${id}` }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["workflows"] }),
  });

  if (isLoading) return <LoadingSpinner />;

  return (
    <div>
      <h1 className="text-base font-semibold text-[#d4d4d4] mb-4">Templates</h1>
      {templates.length === 0 && (
        <p className="text-sm text-[#858585]">No templates yet. Create one from a workflow.</p>
      )}
      <div className="grid grid-cols-2 gap-4">
        {templates.map((t) => (
          <div key={t.id} className="border border-[#3e3e42] rounded-lg p-4 bg-[#252526]">
            <h2 className="font-medium text-sm text-[#d4d4d4]">{t.name}</h2>
            {t.description && <p className="text-xs text-[#858585] mt-1">{t.description}</p>}
            <div className="flex gap-1 mt-2 flex-wrap">
              {t.tags?.map((tag) => (
                <span key={tag} className="text-xs bg-[#37373d] text-[#858585] px-2 py-0.5 rounded">{tag}</span>
              ))}
            </div>
            <button
              onClick={() => clone.mutate(t.id)}
              disabled={clone.isPending}
              className="mt-3 text-sm bg-[#007acc] text-white px-3 py-1.5 rounded hover:bg-[#0069ac] disabled:opacity-50 transition-colors"
            >
              Clone
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
