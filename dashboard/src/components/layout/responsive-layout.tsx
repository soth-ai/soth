"use client";

import { useEffect, useState } from "react";
import { DockNav } from "./dock-nav";

interface ResponsiveLayoutProps {
  children: React.ReactNode;
}

export function ResponsiveLayout({ children }: ResponsiveLayoutProps) {
  const [mounted, setMounted] = useState(false);

  // Prevent hydration mismatch
  useEffect(() => {
    setMounted(true);
  }, []);

  // Don't render layout until mounted to prevent hydration issues
  if (!mounted) {
    return (
      <div className="min-h-screen bg-background">
        {children}
      </div>
    );
  }

  return (
    <>
      <div className="flex min-h-screen flex-col pb-24">
        <main className="flex-1">{children}</main>
      </div>

      <DockNav />
    </>
  );
}
