"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { login } from "@/src/api";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const { access_token } = await login(email, password);
      localStorage.setItem("token", access_token);
      router.push("/");
    } catch {
      setError("Invalid email or password");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-full flex items-center justify-center bg-[#1e1e1e]">
      <div className="w-full max-w-sm bg-[#252526] border border-[#3e3e42] rounded-lg p-8">
        <h1 className="text-lg font-semibold text-[#d4d4d4] mb-1">FluxEngine</h1>
        <p className="text-sm text-[#858585] mb-6">Sign in to continue</p>
        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <div className="flex flex-col gap-1.5">
            <label className="text-xs text-[#858585] uppercase tracking-wide">Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="bg-[#3c3c3c] border border-[#3e3e42] rounded px-3 py-2 text-sm text-[#d4d4d4] focus:outline-none focus:border-[#007acc] placeholder-[#858585]"
              required
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <label className="text-xs text-[#858585] uppercase tracking-wide">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="bg-[#3c3c3c] border border-[#3e3e42] rounded px-3 py-2 text-sm text-[#d4d4d4] focus:outline-none focus:border-[#007acc]"
              required
            />
          </div>
          {error && <p className="text-sm text-[#f14c4c]">{error}</p>}
          <button
            type="submit"
            disabled={loading}
            className="bg-[#007acc] text-white rounded py-2 text-sm font-medium hover:bg-[#0069ac] disabled:opacity-50 transition-colors"
          >
            {loading ? "Signing in..." : "Sign in"}
          </button>
        </form>
      </div>
    </div>
  );
}
