"use client";

import { useState, useEffect } from "react";
import { Sidebar } from "./sidebar";
import { TopBar } from "./top-bar";
import { MobileNav } from "./mobile-nav";
import { MobileMenu } from "./mobile-menu";
import { useIsMobile } from "@/hooks/useMobile";

interface ResponsiveLayoutProps {
  children: React.ReactNode;
}

export function ResponsiveLayout({ children }: ResponsiveLayoutProps) {
  const isMobile = useIsMobile();
  const [menuOpen, setMenuOpen] = useState(false);
  const [mounted, setMounted] = useState(false);

  // Prevent hydration mismatch
  useEffect(() => {
    setMounted(true);
  }, []);

  // Close menu when switching from mobile to desktop
  useEffect(() => {
    if (!isMobile) {
      setMenuOpen(false);
    }
  }, [isMobile]);

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
      {/* Desktop Sidebar */}
      {!isMobile && <Sidebar />}

      {/* Main Content Area */}
      <div
        className={`flex flex-col min-h-screen transition-all duration-300 ${
          isMobile ? "ml-0 pb-16" : "ml-16"
        }`}
      >
        {/* TopBar - hidden on mobile */}
        {!isMobile && <TopBar />}

        {/* Mobile Header - shown only on mobile */}
        {isMobile && <MobileHeader onMenuClick={() => setMenuOpen(true)} />}

        {/* Main Content */}
        <main className="flex-1">{children}</main>
      </div>

      {/* Mobile Bottom Navigation */}
      {isMobile && <MobileNav onMenuClick={() => setMenuOpen(true)} />}

      {/* Mobile Menu Drawer */}
      {isMobile && <MobileMenu isOpen={menuOpen} onClose={() => setMenuOpen(false)} />}
    </>
  );
}

function MobileHeader({ onMenuClick }: { onMenuClick: () => void }) {
  return (
    <header className="sticky top-0 z-30 h-14 bg-card/95 backdrop-blur-sm border-b border-border flex items-center justify-between px-4 safe-area-top">
      <div className="flex items-center gap-2">
        <div className="h-8 w-8 rounded-lg bg-gradient-to-br from-accent to-accent/60 flex items-center justify-center">
          <span className="text-sm font-bold text-accent-foreground">S</span>
        </div>
        <span className="font-semibold text-foreground">SOTH</span>
      </div>

      <div className="flex items-center gap-2">
        <StatusIndicator />
      </div>
    </header>
  );
}

function StatusIndicator() {
  // Simplified status for mobile
  return (
    <div className="flex items-center gap-1.5 px-2 py-1 rounded-full bg-success/10">
      <span className="h-1.5 w-1.5 rounded-full bg-success animate-pulse" />
      <span className="text-xs font-medium text-success">Live</span>
    </div>
  );
}
