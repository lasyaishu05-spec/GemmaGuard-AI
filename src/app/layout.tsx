import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "GemmaGuard AI // Graph-RAG Code Reviewer & Auto-Healer",
  description:
    "Enterprise code vulnerability scanner and autonomous patch synthesis powered by 100% open-weights Gemma 2 9B & 27B models.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="h-full bg-[#f8fafc]">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="h-full bg-[#f8fafc] text-slate-800 antialiased overflow-hidden selection:bg-emerald-100 selection:text-emerald-900">
        {children}
      </body>
    </html>
  );
}
