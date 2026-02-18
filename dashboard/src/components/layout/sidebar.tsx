"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Pulse,
  Binoculars,
  Gear,
  Key,
  CaretLeft,
  CaretRight,
} from "@phosphor-icons/react";
import { cn } from "@/lib/utils";

interface NavItem {
  label: string;
  href: string;
  icon: React.ElementType;
  description?: string;
}

const navItems: NavItem[] = [
  {
    label: "Overview",
    href: "/",
    icon: Pulse,
    description: "High-level runtime state",
  },
  {
    label: "Debug",
    href: "/debug",
    icon: Binoculars,
    description: "MCP/Agent/AI diagnostics",
  },
];

const bottomNavItems: NavItem[] = [
  {
    label: "Settings",
    href: "/settings",
    icon: Gear,
    description: "Configuration",
  },
];

export function Sidebar() {
  const pathname = usePathname();
  const [isExpanded, setIsExpanded] = useState(false);
  const [isPinned, setIsPinned] = useState(false);

  const shouldExpand = isExpanded || isPinned;

  return (
    <aside
      onMouseEnter={() => setIsExpanded(true)}
      onMouseLeave={() => setIsExpanded(false)}
      className={cn(
        "fixed left-0 top-0 h-screen border-r border-border bg-card/50 backdrop-blur-sm flex flex-col z-40 transition-all duration-300 ease-out",
        shouldExpand ? "w-64" : "w-16"
      )}
    >
      {/* Logo */}
      <div className={cn(
        "h-14 border-b border-border flex items-center",
        shouldExpand ? "px-4" : "px-0 justify-center"
      )}>
        <Link href="/" className="flex items-center gap-3">
          <div className="h-9 w-9 rounded-xl bg-gradient-to-br from-accent to-accent/60 flex items-center justify-center shadow-lg shadow-accent/20 shrink-0">
            <Key className="h-5 w-5 text-accent-foreground" weight="bold" />
          </div>
          <div className={cn(
            "overflow-hidden transition-all duration-300",
            shouldExpand ? "w-auto opacity-100" : "w-0 opacity-0"
          )}>
            <h1 className="text-lg font-bold tracking-tight whitespace-nowrap">SOTH</h1>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider whitespace-nowrap">
              AI Control Plane
            </p>
          </div>
        </Link>
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-4 space-y-1">
        {navItems.map((item) => {
          const isActive =
            pathname === item.href ||
            (item.href !== "/" && pathname.startsWith(item.href));

          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-3 mx-2 rounded-lg transition-all duration-200 group relative",
                shouldExpand ? "px-3 py-2.5" : "px-0 py-2.5 justify-center",
                isActive
                  ? "bg-accent text-accent-foreground shadow-sm"
                  : "text-muted-foreground hover:text-foreground hover:bg-muted"
              )}
            >
              <item.icon
                className={cn(
                  "h-5 w-5 transition-transform shrink-0",
                  isActive && "scale-110"
                )}
                weight={isActive ? "fill" : "duotone"}
              />
              <div className={cn(
                "flex-1 min-w-0 overflow-hidden transition-all duration-300",
                shouldExpand ? "opacity-100" : "opacity-0 w-0"
              )}>
                <span className="text-sm font-medium whitespace-nowrap">{item.label}</span>
                {item.description && (
                  <p
                    className={cn(
                      "text-[10px] truncate whitespace-nowrap",
                      isActive
                        ? "text-accent-foreground/70"
                        : "text-muted-foreground/70"
                    )}
                  >
                    {item.description}
                  </p>
                )}
              </div>

              {/* Tooltip for collapsed state */}
              {!shouldExpand && (
                <div className="absolute left-full ml-2 px-2 py-1 bg-card border border-border rounded-md shadow-lg opacity-0 group-hover:opacity-100 pointer-events-none transition-opacity whitespace-nowrap z-50">
                  <span className="text-sm font-medium">{item.label}</span>
                </div>
              )}
            </Link>
          );
        })}
      </nav>

      {/* Bottom Navigation */}
      <div className="py-4 border-t border-border space-y-1">
        {bottomNavItems.map((item) => {
          const isActive = pathname === item.href;

          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-3 mx-2 rounded-lg transition-all duration-200 group relative",
                shouldExpand ? "px-3 py-2.5" : "px-0 py-2.5 justify-center",
                isActive
                  ? "bg-accent text-accent-foreground shadow-sm"
                  : "text-muted-foreground hover:text-foreground hover:bg-muted"
              )}
            >
              <item.icon
                className="h-5 w-5 shrink-0"
                weight={isActive ? "fill" : "duotone"}
              />
              <span className={cn(
                "text-sm font-medium overflow-hidden transition-all duration-300 whitespace-nowrap",
                shouldExpand ? "opacity-100" : "opacity-0 w-0"
              )}>
                {item.label}
              </span>

              {/* Tooltip for collapsed state */}
              {!shouldExpand && (
                <div className="absolute left-full ml-2 px-2 py-1 bg-card border border-border rounded-md shadow-lg opacity-0 group-hover:opacity-100 pointer-events-none transition-opacity whitespace-nowrap z-50">
                  <span className="text-sm font-medium">{item.label}</span>
                </div>
              )}
            </Link>
          );
        })}

        {/* Pin Toggle */}
        <button
          onClick={() => setIsPinned(!isPinned)}
          className={cn(
            "flex items-center gap-3 mx-2 rounded-lg transition-all duration-200 text-muted-foreground hover:text-foreground hover:bg-muted",
            shouldExpand ? "px-3 py-2" : "px-0 py-2 justify-center"
          )}
          title={isPinned ? "Collapse sidebar" : "Pin sidebar"}
        >
          {isPinned ? (
            <CaretLeft className="h-4 w-4 shrink-0" weight="bold" />
          ) : (
            <CaretRight className="h-4 w-4 shrink-0" weight="bold" />
          )}
          <span className={cn(
            "text-xs overflow-hidden transition-all duration-300 whitespace-nowrap",
            shouldExpand ? "opacity-100" : "opacity-0 w-0"
          )}>
            {isPinned ? "Collapse" : "Pin sidebar"}
          </span>
        </button>
      </div>

      {/* Footer */}
      <div className={cn(
        "py-3 border-t border-border",
        shouldExpand ? "px-4" : "px-0 flex justify-center"
      )}>
        <div className={cn(
          "flex items-center gap-2 text-xs text-muted-foreground",
          !shouldExpand && "flex-col"
        )}>
          <Gear className="h-3.5 w-3.5 shrink-0" />
          <span className={cn(
            "transition-all duration-300",
            shouldExpand ? "opacity-100" : "opacity-0 hidden"
          )}>
            v0.1.0
          </span>
        </div>
      </div>
    </aside>
  );
}
