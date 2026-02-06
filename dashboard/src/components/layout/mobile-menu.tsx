"use client";

import { useEffect } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  X,
  Gear,
  Key,
  Bell,
  Moon,
  Sun,
  Command,
  Info,
} from "@phosphor-icons/react";
import { useSettingsStore } from "@/store/settings";
import { useCommandPalette } from "@/store/command-palette";
import { cn } from "@/lib/utils";

interface MobileMenuProps {
  isOpen: boolean;
  onClose: () => void;
}

export function MobileMenu({ isOpen, onClose }: MobileMenuProps) {
  const pathname = usePathname();
  const theme = useSettingsStore((state) => state.theme);
  const updateSettings = useSettingsStore((state) => state.updateSettings);
  const { open: openCommandPalette } = useCommandPalette();

  // Close menu on route change
  useEffect(() => {
    onClose();
  }, [pathname, onClose]);

  // Prevent body scroll when menu is open
  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = "hidden";
    } else {
      document.body.style.overflow = "";
    }
    return () => {
      document.body.style.overflow = "";
    };
  }, [isOpen]);

  const toggleTheme = () => {
    const newTheme = theme === "dark" ? "light" : "dark";
    updateSettings({ theme: newTheme });
  };

  if (!isOpen) return null;

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-background/80 backdrop-blur-sm z-50 md:hidden"
        onClick={onClose}
      />

      {/* Menu Panel */}
      <div className="fixed inset-y-0 right-0 w-[280px] bg-card border-l border-border z-50 md:hidden animate-slide-in-right">
        {/* Header */}
        <div className="flex items-center justify-between h-14 px-4 border-b border-border">
          <div className="flex items-center gap-2">
            <div className="h-8 w-8 rounded-lg bg-gradient-to-br from-accent to-accent/60 flex items-center justify-center">
              <Key className="h-4 w-4 text-accent-foreground" weight="bold" />
            </div>
            <span className="font-semibold">SOTH</span>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-lg hover:bg-muted transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Menu Content */}
        <div className="p-4 space-y-6">
          {/* Quick Actions */}
          <div className="space-y-1">
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider px-2 mb-2">
              Quick Actions
            </h3>

            <button
              onClick={() => {
                onClose();
                openCommandPalette();
              }}
              className="flex items-center gap-3 w-full px-3 py-2.5 rounded-lg hover:bg-muted transition-colors"
            >
              <Command className="h-5 w-5 text-muted-foreground" />
              <span className="text-sm font-medium">Search</span>
              <kbd className="ml-auto text-[10px] font-mono text-muted-foreground bg-muted px-1.5 py-0.5 rounded">
                ⌘K
              </kbd>
            </button>

            <button
              onClick={toggleTheme}
              className="flex items-center gap-3 w-full px-3 py-2.5 rounded-lg hover:bg-muted transition-colors"
            >
              {theme === "dark" ? (
                <Sun className="h-5 w-5 text-muted-foreground" />
              ) : (
                <Moon className="h-5 w-5 text-muted-foreground" />
              )}
              <span className="text-sm font-medium">
                {theme === "dark" ? "Light Mode" : "Dark Mode"}
              </span>
            </button>

            <button className="flex items-center gap-3 w-full px-3 py-2.5 rounded-lg hover:bg-muted transition-colors">
              <Bell className="h-5 w-5 text-muted-foreground" />
              <span className="text-sm font-medium">Notifications</span>
              <span className="ml-auto text-xs text-muted-foreground">0</span>
            </button>
          </div>

          {/* Navigation */}
          <div className="space-y-1">
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider px-2 mb-2">
              Settings
            </h3>

            <Link
              href="/settings"
              className={cn(
                "flex items-center gap-3 w-full px-3 py-2.5 rounded-lg transition-colors",
                pathname === "/settings"
                  ? "bg-accent text-accent-foreground"
                  : "hover:bg-muted"
              )}
            >
              <Gear className="h-5 w-5" weight={pathname === "/settings" ? "fill" : "regular"} />
              <span className="text-sm font-medium">Settings</span>
            </Link>
          </div>

          {/* Footer Info */}
          <div className="pt-4 border-t border-border">
            <div className="flex items-center gap-2 px-2 text-xs text-muted-foreground">
              <Info className="h-4 w-4" />
              <span>SOTH v0.1.0</span>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
