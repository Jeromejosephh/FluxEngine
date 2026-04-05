import type { Metadata } from "next";
import { Geist } from "next/font/google";
import "./globals.css";
import { Providers } from "@/src/providers";

const geist = Geist({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "FluxEngine",
  description: "Workflow automation engine",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="h-full dark">
      <body className={`${geist.className} h-full bg-[#1e1e1e] text-[#d4d4d4]`}>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
