"use client";

import { useRouter } from "next/navigation";

const TEMPLATES = [
  {
    id: "job_tracker",
    icon: "💼",
    name: "Job Tracker",
    description: "Track job applications and get email reminders for follow-ups.",
  },
  {
    id: "expense_tracker",
    icon: "💰",
    name: "Expense Tracker",
    description: "Log expenses and get weekly email summaries.",
  },
  {
    id: "contact_followup",
    icon: "👥",
    name: "Contact Follow-up",
    description: "Keep track of people you need to follow up with and get reminders.",
  },
];

const btnPrimary = "bg-[#007acc] text-white rounded px-3 py-1.5 text-sm font-medium hover:bg-[#0069ac] transition-colors w-full";
const btnSecondary = "border border-[#3e3e42] rounded px-3 py-1.5 text-sm text-[#d4d4d4] hover:bg-[#37373d] transition-colors w-full";

export default function DashboardPage() {
  const router = useRouter();

  return (
    <div className="max-w-2xl">
      <h1 className="text-base font-semibold text-[#d4d4d4] mb-1">Welcome to FluxEngine</h1>
      <p className="text-xs text-[#858585] mb-8">Pick a template to get started, or build your own workflow from scratch.</p>

      <h2 className="text-xs font-medium text-[#858585] uppercase tracking-wider mb-3">Quick Start</h2>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
        {TEMPLATES.map((t) => (
          <div key={t.id} className="border border-[#3e3e42] rounded-lg p-4 bg-[#252526] flex flex-col gap-3">
            <div className="text-2xl">{t.icon}</div>
            <div className="flex-1">
              <h3 className="font-semibold text-sm text-[#d4d4d4]">{t.name}</h3>
              <p className="text-xs text-[#858585] mt-1">{t.description}</p>
            </div>
            <button onClick={() => router.push("/templates")} className={btnPrimary}>
              Use template
            </button>
          </div>
        ))}
      </div>

      <div className="border border-dashed border-[#3e3e42] rounded-lg p-4 bg-[#1e1e1e] flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-[#d4d4d4]">Build your own</p>
          <p className="text-xs text-[#858585] mt-0.5">Create a custom workflow with your own steps and schedule.</p>
        </div>
        <button onClick={() => router.push("/workflows")} className="border border-[#3e3e42] rounded px-3 py-1.5 text-sm text-[#d4d4d4] hover:bg-[#37373d] transition-colors shrink-0 ml-4">
          Create workflow →
        </button>
      </div>
    </div>
  );
}
