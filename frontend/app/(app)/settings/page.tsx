"use client";

import { useQuery } from "@tanstack/react-query";
import { getMe } from "@/src/api";

export default function SettingsPage() {
  const { data: user } = useQuery({
    queryKey: ["me"],
    queryFn: getMe,
  });

  const u = user as { full_name?: string; email?: string; role?: string } | undefined;

  return (
    <div>
      <h1 className="text-base font-semibold text-[#d4d4d4] mb-4">Settings</h1>
      <div className="border border-[#3e3e42] rounded-lg p-4 max-w-sm bg-[#252526]">
        <p className="text-xs text-[#858585] uppercase tracking-wide mb-3">Account</p>
        <p className="text-sm font-medium text-[#d4d4d4]">{u?.full_name}</p>
        <p className="text-sm text-[#858585]">{u?.email}</p>
        <span className="mt-2 inline-block text-xs bg-[#37373d] text-[#858585] px-2 py-0.5 rounded capitalize">{u?.role}</span>
      </div>
    </div>
  );
}
