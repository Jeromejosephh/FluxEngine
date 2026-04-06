"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";

const BASE_URL = "https://fluxengine-production.up.railway.app";

interface Column { name: string; type: string; nullable: boolean; }
interface FormSchema { table_name: string; description: string; columns: Column[]; token: string; }

const inputCls = "bg-white border border-gray-300 rounded-lg px-4 py-2.5 text-sm text-gray-800 focus:outline-none focus:border-blue-500 w-full";
const btnPrimary = "bg-blue-600 text-white rounded-lg px-6 py-2.5 text-sm font-medium hover:bg-blue-700 disabled:opacity-50 transition-colors w-full";

function inputType(colType: string): string {
  if (colType === "INTEGER" || colType === "FLOAT") return "number";
  if (colType === "DATE") return "date";
  if (colType === "BOOLEAN") return "checkbox";
  return "text";
}

export default function FormPage() {
  const { token } = useParams<{ token: string }>();
  const [schema, setSchema] = useState<FormSchema | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [values, setValues] = useState<Record<string, string>>({});
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    fetch(`${BASE_URL}/forms/${token}`)
      .then((r) => r.ok ? r.json() : Promise.reject())
      .then((data: FormSchema) => {
        setSchema(data);
        setValues(Object.fromEntries(data.columns.map((c) => [c.name, ""])));
      })
      .catch(() => setNotFound(true));
  }, [token]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setError("");
    try {
      const payload: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(values)) {
        if (v !== "") payload[k] = v;
      }
      const res = await fetch(`${BASE_URL}/webhooks/inbound/${token}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!res.ok) throw new Error("Submission failed");
      setSubmitted(true);
    } catch {
      setError("Something went wrong. Please try again.");
    } finally {
      setSubmitting(false);
    }
  }

  if (notFound) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center p-4">
        <div className="text-center">
          <p className="text-gray-500 text-sm">This form is not available.</p>
        </div>
      </div>
    );
  }

  if (!schema) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="w-6 h-6 border-2 border-blue-600 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (submitted) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center p-4">
        <div className="bg-white rounded-2xl shadow-sm border border-gray-200 p-8 w-full max-w-md text-center">
          <div className="text-4xl mb-3">✓</div>
          <h1 className="text-lg font-semibold text-gray-800 mb-1">Submitted!</h1>
          <p className="text-sm text-gray-500">Your response has been recorded.</p>
          <button
            onClick={() => { setSubmitted(false); setValues(Object.fromEntries(schema.columns.map((c) => [c.name, ""]))); }}
            className="mt-6 text-sm text-blue-600 hover:underline"
          >
            Submit another response
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center p-4">
      <div className="bg-white rounded-2xl shadow-sm border border-gray-200 p-8 w-full max-w-md">
        <h1 className="text-xl font-semibold text-gray-800 mb-1">{schema.table_name}</h1>
        {schema.description && <p className="text-sm text-gray-500 mb-6">{schema.description}</p>}

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          {schema.columns.map((col) => (
            <div key={col.name}>
              <label className="block text-sm font-medium text-gray-700 mb-1 capitalize">
                {col.name.replace(/_/g, " ")}
              </label>
              {col.type === "BOOLEAN" ? (
                <select
                  value={values[col.name] ?? ""}
                  onChange={(e) => setValues((p) => ({ ...p, [col.name]: e.target.value }))}
                  className={inputCls}
                >
                  <option value="">Select...</option>
                  <option value="true">Yes</option>
                  <option value="false">No</option>
                </select>
              ) : (
                <input
                  type={inputType(col.type)}
                  value={values[col.name] ?? ""}
                  onChange={(e) => setValues((p) => ({ ...p, [col.name]: e.target.value }))}
                  className={inputCls}
                  step={col.type === "FLOAT" ? "any" : undefined}
                />
              )}
            </div>
          ))}

          {error && <p className="text-sm text-red-500">{error}</p>}

          <button type="submit" disabled={submitting} className={btnPrimary}>
            {submitting ? "Submitting..." : "Submit"}
          </button>
        </form>
      </div>
    </div>
  );
}
