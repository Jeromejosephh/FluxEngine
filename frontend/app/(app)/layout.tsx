import { Sidebar } from "@/components/Sidebar";
import { AuthGuard } from "@/components/AuthGuard";

export default function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <AuthGuard>
      <div className="flex h-full bg-[#1e1e1e]">
        <Sidebar />
        <main className="flex-1 overflow-auto p-6 text-[#d4d4d4]">{children}</main>
      </div>
    </AuthGuard>
  );
}
