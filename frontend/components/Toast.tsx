"use client";

import { useEffect, useState } from "react";

interface Toast { id: number; message: string; type: "success" | "error"; }

let _nextId = 0;

export function showToast(message: string, type: "success" | "error" = "success") {
  if (typeof window === "undefined") return;
  window.dispatchEvent(new CustomEvent("flux-toast", { detail: { id: ++_nextId, message, type } }));
}

export function ToastContainer() {
  const [toasts, setToasts] = useState<Toast[]>([]);

  useEffect(() => {
    const handler = (e: Event) => {
      const toast = (e as CustomEvent).detail as Toast;
      setToasts((prev) => [...prev, toast]);
      setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== toast.id)), 3500);
    };
    window.addEventListener("flux-toast", handler);
    return () => window.removeEventListener("flux-toast", handler);
  }, []);

  return (
    <div className="fixed bottom-4 right-4 flex flex-col gap-2 z-[100] pointer-events-none">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={`px-4 py-2.5 rounded-lg text-sm font-medium shadow-lg ${
            t.type === "success"
              ? "bg-[#1e3a2f] text-[#4ec9b0] border border-[#2a5a3f]"
              : "bg-[#3a1e1e] text-[#f14c4c] border border-[#5a2a2a]"
          }`}
        >
          {t.message}
        </div>
      ))}
    </div>
  );
}
