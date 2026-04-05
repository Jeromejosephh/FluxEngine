"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";

const links = [
  { href: "/tables", label: "Tables" },
  { href: "/workflows", label: "Workflows" },
  { href: "/logs", label: "Logs" },
  { href: "/templates", label: "Templates" },
  { href: "/settings", label: "Settings" },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-52 shrink-0 border-r border-[#3e3e42] bg-[#252526] flex flex-col h-full">
      <div className="px-4 py-4 border-b border-[#3e3e42]">
        <span className="font-semibold text-sm text-[#d4d4d4] tracking-wide">FluxEngine</span>
      </div>
      <nav className="flex flex-col gap-0.5 p-2 flex-1">
        {links.map((link) => (
          <Link
            key={link.href}
            href={link.href}
            className={cn(
              "px-3 py-1.5 rounded text-sm text-[#858585] hover:text-[#d4d4d4] hover:bg-[#37373d] transition-colors",
              pathname.startsWith(link.href) &&
                "bg-[#37373d] text-[#d4d4d4] border-l-2 border-[#007acc]"
            )}
          >
            {link.label}
          </Link>
        ))}
      </nav>
      <div className="p-4 border-t border-[#3e3e42]">
        <button
          onClick={() => {
            localStorage.removeItem("token");
            window.location.href = "/login";
          }}
          className="text-xs text-[#858585] hover:text-[#d4d4d4]"
        >
          Sign out
        </button>
      </div>
    </aside>
  );
}
