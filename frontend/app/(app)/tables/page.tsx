"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "@/lib/api";
import { LoadingSpinner } from "@/components/LoadingSpinner";

interface Column { name: string; type: string; }
interface Table {
  id: number; name: string; description: string;
  schema_definition: { columns: Column[] }; created_at: string;
}
interface TableData { rows: Record<string, unknown>[]; total: number; }

const COLUMN_TYPES = ["VARCHAR", "INTEGER", "FLOAT", "BOOLEAN", "DATE", "TIMESTAMP"];

const inputCls = "bg-[#3c3c3c] border border-[#3e3e42] rounded px-3 py-2 text-sm text-[#d4d4d4] focus:outline-none focus:border-[#007acc] placeholder-[#858585] w-full";
const btnPrimary = "bg-[#007acc] text-white rounded px-3 py-2 text-sm font-medium hover:bg-[#0069ac] disabled:opacity-50 transition-colors";
const btnSecondary = "border border-[#3e3e42] rounded px-3 py-2 text-sm text-[#d4d4d4] hover:bg-[#37373d] transition-colors";

export default function TablesPage() {
  const qc = useQueryClient();
  const [selectedTable, setSelectedTable] = useState<Table | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [newTableName, setNewTableName] = useState("");
  const [newTableDesc, setNewTableDesc] = useState("");
  const [columns, setColumns] = useState<Column[]>([{ name: "", type: "VARCHAR" }]);
  const [newRow, setNewRow] = useState<Record<string, string>>({});
  const [showAddRow, setShowAddRow] = useState(false);
  const [createError, setCreateError] = useState("");

  const { data: tables = [], isLoading, isError } = useQuery<Table[]>({
    queryKey: ["tables"],
    queryFn: () => api.get("/api/tables"),
  });

  const { data: tableData } = useQuery<TableData>({
    queryKey: ["tableData", selectedTable?.id],
    queryFn: () => api.get(`/api/tables/${selectedTable!.id}/data`),
    enabled: !!selectedTable,
  });

  const createTable = useMutation({
    mutationFn: () =>
      api.post("/api/tables", {
        name: newTableName,
        description: newTableDesc,
        schema_definition: { columns: columns.filter((c) => c.name) },
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["tables"] });
      setShowCreate(false);
      setNewTableName(""); setNewTableDesc("");
      setColumns([{ name: "", type: "VARCHAR" }]);
      setCreateError("");
    },
    onError: (e: Error) => setCreateError(e.message),
  });

  const addRow = useMutation({
    mutationFn: () => api.post(`/api/tables/${selectedTable!.id}/data`, { rows: [newRow] }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["tableData", selectedTable?.id] });
      setNewRow({}); setShowAddRow(false);
    },
  });

  const deleteTable = useMutation({
    mutationFn: (id: number) => api.delete(`/api/tables/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["tables"] });
      setSelectedTable(null);
    },
  });

  const cols = selectedTable?.schema_definition?.columns ?? [];
  const rows = tableData?.rows ?? [];

  if (isLoading) return <LoadingSpinner />;
  if (isError) return <p className="text-sm text-[#f14c4c]">Failed to load tables.</p>;

  return (
    <div className="flex gap-6 h-full">
      {/* Table list */}
      <div className="w-48 shrink-0">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-xs font-medium text-[#858585] uppercase tracking-wider">Tables</h2>
          <button onClick={() => setShowCreate(true)} className="text-xs text-[#007acc] hover:text-[#4db8ff]">+ New</button>
        </div>
        <div className="flex flex-col gap-0.5">
          {tables.map((t) => (
            <button
              key={t.id}
              onClick={() => setSelectedTable(t)}
              className={`text-left px-3 py-1.5 rounded text-sm truncate transition-colors ${
                selectedTable?.id === t.id
                  ? "bg-[#37373d] text-[#d4d4d4] border-l-2 border-[#007acc]"
                  : "text-[#858585] hover:text-[#d4d4d4] hover:bg-[#2a2d2e]"
              }`}
            >
              {t.name}
            </button>
          ))}
          {tables.length === 0 && <p className="text-xs text-[#858585] px-1">No tables yet</p>}
        </div>
      </div>

      {/* Table content */}
      <div className="flex-1 min-w-0">
        {!selectedTable ? (
          <div className="flex items-center justify-center h-64 text-[#858585] text-sm">
            Select a table or create one
          </div>
        ) : (
          <div>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h1 className="text-base font-semibold text-[#d4d4d4]">{selectedTable.name}</h1>
                {selectedTable.description && (
                  <p className="text-xs text-[#858585] mt-0.5">{selectedTable.description}</p>
                )}
              </div>
              <div className="flex gap-2">
                <button onClick={() => setShowAddRow(true)} className={btnPrimary}>+ Add row</button>
                <button
                  onClick={() => deleteTable.mutate(selectedTable.id)}
                  className="text-sm text-[#f14c4c] hover:text-red-400 px-3 py-2"
                >
                  Delete
                </button>
              </div>
            </div>

            <div className="border border-[#3e3e42] rounded overflow-auto">
              <table className="w-full text-sm">
                <thead className="bg-[#2d2d2d] border-b border-[#3e3e42]">
                  <tr>
                    <th className="text-left px-3 py-2 text-[#858585] font-medium w-10">#</th>
                    {cols.map((c) => (
                      <th key={c.name} className="text-left px-3 py-2 text-[#858585] font-medium">
                        {c.name}
                        <span className="ml-1 text-xs text-[#4e4e4e]">{c.type}</span>
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row, i) => (
                    <tr key={i} className="border-t border-[#3e3e42] hover:bg-[#2a2d2e]">
                      <td className="px-3 py-2 text-[#4e4e4e]">{i + 1}</td>
                      {cols.map((c) => (
                        <td key={c.name} className="px-3 py-2 text-[#d4d4d4]">
                          {String(row[c.name] ?? "")}
                        </td>
                      ))}
                    </tr>
                  ))}
                  {rows.length === 0 && (
                    <tr>
                      <td colSpan={cols.length + 1} className="px-3 py-8 text-center text-[#858585]">
                        No rows yet
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            <p className="text-xs text-[#858585] mt-2">{tableData?.total ?? 0} rows</p>
          </div>
        )}
      </div>

      {/* Create table modal */}
      {showCreate && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-[#252526] border border-[#3e3e42] rounded-lg p-6 w-full max-w-md">
            <h2 className="font-semibold text-[#d4d4d4] mb-4">New table</h2>
            <div className="flex flex-col gap-3">
              <input placeholder="Table name" value={newTableName} onChange={(e) => setNewTableName(e.target.value)} className={inputCls} />
              <input placeholder="Description (optional)" value={newTableDesc} onChange={(e) => setNewTableDesc(e.target.value)} className={inputCls} />
              <div>
                <p className="text-xs text-[#858585] uppercase tracking-wide mb-2">Columns</p>
                <div className="flex flex-col gap-2">
                  {columns.map((col, i) => (
                    <div key={i} className="flex gap-2">
                      <input
                        placeholder="Column name"
                        value={col.name}
                        onChange={(e) => {
                          const updated = [...columns];
                          updated[i] = { ...updated[i], name: e.target.value };
                          setColumns(updated);
                        }}
                        className={inputCls}
                      />
                      <select
                        value={col.type}
                        onChange={(e) => {
                          const updated = [...columns];
                          updated[i] = { ...updated[i], type: e.target.value };
                          setColumns(updated);
                        }}
                        className="bg-[#3c3c3c] border border-[#3e3e42] rounded px-2 py-2 text-sm text-[#d4d4d4] focus:outline-none focus:border-[#007acc]"
                      >
                        {COLUMN_TYPES.map((t) => <option key={t}>{t}</option>)}
                      </select>
                      {columns.length > 1 && (
                        <button onClick={() => setColumns(columns.filter((_, j) => j !== i))} className="text-[#858585] hover:text-[#f14c4c] text-sm">✕</button>
                      )}
                    </div>
                  ))}
                  <button onClick={() => setColumns([...columns, { name: "", type: "VARCHAR" }])} className="text-sm text-[#007acc] hover:text-[#4db8ff] text-left">
                    + Add column
                  </button>
                </div>
              </div>
              {createError && <p className="text-sm text-[#f14c4c]">{createError}</p>}
              <div className="flex gap-2 pt-2">
                <button onClick={() => createTable.mutate()} disabled={!newTableName || createTable.isPending} className={`flex-1 ${btnPrimary}`}>
                  {createTable.isPending ? "Creating..." : "Create"}
                </button>
                <button onClick={() => setShowCreate(false)} className={`flex-1 ${btnSecondary}`}>Cancel</button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Add row modal */}
      {showAddRow && selectedTable && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-[#252526] border border-[#3e3e42] rounded-lg p-6 w-full max-w-md">
            <h2 className="font-semibold text-[#d4d4d4] mb-4">Add row</h2>
            <div className="flex flex-col gap-3">
              {cols.map((col) => (
                <div key={col.name} className="flex flex-col gap-1.5">
                  <label className="text-xs text-[#858585] uppercase tracking-wide">{col.name}</label>
                  <input
                    placeholder={col.type}
                    value={newRow[col.name] ?? ""}
                    onChange={(e) => setNewRow({ ...newRow, [col.name]: e.target.value })}
                    className={inputCls}
                  />
                </div>
              ))}
              <div className="flex gap-2 pt-2">
                <button onClick={() => addRow.mutate()} disabled={addRow.isPending} className={`flex-1 ${btnPrimary}`}>
                  {addRow.isPending ? "Adding..." : "Add row"}
                </button>
                <button onClick={() => setShowAddRow(false)} className={`flex-1 ${btnSecondary}`}>Cancel</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
