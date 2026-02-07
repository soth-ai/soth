"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Gear } from "@phosphor-icons/react";
import { cn } from "@/lib/utils";
import { CostLogo, IdentityLogo, MetricLogo, ObserverLogo } from "./dock-icons";

interface NavItem {
  label: string;
  href: string;
  icon: React.ElementType;
}

const navItems: NavItem[] = [
  { label: "Overview", href: "/", icon: MetricLogo },
  { label: "Observe", href: "/observability", icon: ObserverLogo },
  { label: "Policy", href: "/policies", icon: IdentityLogo },
  { label: "Budget", href: "/budget", icon: CostLogo },
  { label: "Settings", href: "/settings", icon: Gear },
];

export function DockNav() {
  const pathname = usePathname();

  return (
    <nav className="pointer-events-none fixed bottom-2 left-1/2 z-50 w-[min(700px,calc(100%-1rem))] -translate-x-1/2 safe-area-bottom">
      <div className="pointer-events-auto grid grid-cols-5 items-center gap-0.5 rounded-xl border border-dashed border-border/80 bg-card/88 p-1 backdrop-blur-xl shadow-[0_14px_40px_-30px_rgba(0,0,0,0.92)]">
        {navItems.map((item) => {
          const isActive =
            pathname === item.href ||
            (item.href !== "/" && pathname.startsWith(item.href));

          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex min-w-0 flex-col items-center justify-center gap-0.5 rounded-lg border border-transparent px-1.5 py-1 text-[9px] font-medium tracking-[0.01em] transition-all md:gap-0.5 md:py-1.5 md:text-[10px]",
                isActive
                  ? "border-primary/35 bg-primary/15 text-primary shadow-[inset_0_0_16px_-12px_rgba(217,119,87,0.7)]"
                  : "text-muted-foreground hover:text-foreground hover:bg-muted/40"
              )}
            >
              <item.icon
                className="h-[14px] w-[14px] shrink-0 md:h-4 md:w-4"
                weight={isActive ? "fill" : "duotone"}
              />
              <span className="truncate leading-none">{item.label}</span>
            </Link>
          );
        })}
      </div>
    </nav>
  );
}
