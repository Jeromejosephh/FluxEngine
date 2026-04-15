"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { getMe, api } from "@/src/api";

export default function SettingsPage() {
  const { data: user } = useQuery({
    queryKey: ["me"],
    queryFn: getMe,
  });

  const u = user as { full_name?: string; email?: string; role?: string } | undefined;
  const [confirming, setConfirming] = useState(false);
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);

  async function handleReset() {
    setLoading(true);
    try {
      await api.delete("/api/auth/reset");
      setDone(true);
      setConfirming(false);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <h1 className="text-base font-semibold text-[#d4d4d4] mb-4">Settings</h1>
      <div className="border border-[#3e3e42] rounded-lg p-4 max-w-sm bg-[#252526]">
        <p className="text-xs text-[#858585] uppercase tracking-wide mb-3">Account</p>
        <p className="text-sm font-medium text-[#d4d4d4]">{u?.full_name}</p>
        <p className="text-sm text-[#858585]">{u?.email}</p>
        <span className="mt-2 inline-block text-xs bg-[#37373d] text-[#858585] px-2 py-0.5 rounded capitalize">{u?.role}</span>
      </div>

      <div className="border border-[#3e3e42] rounded-lg p-4 max-w-sm bg-[#252526] mt-4">
        <p className="text-xs text-[#858585] uppercase tracking-wide mb-3">Danger Zone</p>
        {done ? (
          <p className="text-sm text-[#4ec9b0]">All workflows and tables deleted.</p>
        ) : confirming ? (
          <div>
            <p className="text-sm text-[#f14c4c] mb-3">This will delete all your workflows and tables. Are you sure?</p>
            <div className="flex gap-2">
              <button
                onClick={handleReset}
                disabled={loading}
                className="px-3 py-1.5 text-sm rounded bg-[#f14c4c] text-white hover:bg-[#d43f3f] disabled:opacity-50"
              >
                {loading ? "Deleting..." : "Yes, delete everything"}
              </button>
              <button
                onClick={() => setConfirming(false)}
                className="px-3 py-1.5 text-sm rounded bg-[#37373d] text-[#d4d4d4] hover:bg-[#3e3e42]"
              >
                Cancel
              </button>
            </div>
          </div>
        ) : (
          <button
            onClick={() => setConfirming(true)}
            className="px-3 py-1.5 text-sm rounded bg-[#37373d] text-[#f14c4c] hover:bg-[#3e3e42]"
          >
            Reset account data
          </button>
        )}
      </div>
    </div>
  );
}
