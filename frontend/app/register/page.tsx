"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { register } from "@/src/api";

const inputCls = "bg-[#3c3c3c] border border-[#3e3e42] rounded px-3 py-2 text-sm text-[#d4d4d4] focus:outline-none focus:border-[#007acc] placeholder-[#858585]";

export default function RegisterPage() {
  const router = useRouter();
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await register(email, password, fullName);
      router.push("/login");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Registration failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-full flex items-center justify-center bg-[#1e1e1e]">
      <div className="w-full max-w-sm bg-[#252526] border border-[#3e3e42] rounded-lg p-8">
        <h1 className="text-lg font-semibold text-[#d4d4d4] mb-1">FluxEngine</h1>
        <p className="text-sm text-[#858585] mb-6">Create your account</p>
        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <div className="flex flex-col gap-1.5">
            <label className="text-xs text-[#858585] uppercase tracking-wide">Full name</label>
            <input type="text" value={fullName} onChange={(e) => setFullName(e.target.value)} className={inputCls} required />
          </div>
          <div className="flex flex-col gap-1.5">
            <label className="text-xs text-[#858585] uppercase tracking-wide">Email</label>
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} className={inputCls} required />
          </div>
          <div className="flex flex-col gap-1.5">
            <label className="text-xs text-[#858585] uppercase tracking-wide">Password</label>
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} className={inputCls} required />
          </div>
          {error && <p className="text-sm text-[#f14c4c]">{error}</p>}
          <button
            type="submit"
            disabled={loading}
            className="bg-[#007acc] text-white rounded py-2 text-sm font-medium hover:bg-[#0069ac] disabled:opacity-50 transition-colors"
          >
            {loading ? "Creating account..." : "Create account"}
          </button>
        </form>
        <p className="text-xs text-[#858585] mt-4 text-center">
          Already have an account?{" "}
          <a href="/login" className="text-[#007acc] hover:underline">Sign in</a>
        </p>
      </div>
    </div>
  );
}
