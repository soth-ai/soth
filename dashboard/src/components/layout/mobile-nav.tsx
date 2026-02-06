"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Pulse,
  Shield,
  CurrencyDollar,
  Binoculars,
  List,
} from "@phosphor-icons/react";
import { cn } from "@/lib/utils";

interface NavItem {
  label: string;
  href: string;
  icon: React.ElementType;
}

const navItems: NavItem[] = [
  { label: "Overview", href: "/", icon: Pulse },
  { label: "Traffic", href: "/observability", icon: Binoculars },
  { label: "Policy", href: "/policies", icon: Shield },
  { label: "Budget", href: "/budget", icon: CurrencyDollar },
];

interface MobileNavProps {
  onMenuClick: () => void;
}

export function MobileNav({ onMenuClick }: MobileNavProps) {
  const pathname = usePathname();

  return (
    <nav className="fixed bottom-0 left-0 right-0 z-50 bg-card border-t border-border md:hidden safe-area-bottom">
      <div className="flex items-center justify-around h-16">
        {navItems.map((item) => {
          const isActive =
            pathname === item.href ||
            (item.href !== "/" && pathname.startsWith(item.href));

          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex flex-col items-center justify-center flex-1 h-full gap-1 transition-colors",
                isActive
                  ? "text-accent"
                  : "text-muted-foreground active:text-foreground"
              )}
            >
              <item.icon
                className="h-5 w-5"
                weight={isActive ? "fill" : "regular"}
              />
              <span className="text-[10px] font-medium">{item.label}</span>
            </Link>
          );
        })}

        {/* Menu button */}
        <button
          onClick={onMenuClick}
          className="flex flex-col items-center justify-center flex-1 h-full gap-1 text-muted-foreground active:text-foreground transition-colors"
        >
          <List className="h-5 w-5" weight="regular" />
          <span className="text-[10px] font-medium">More</span>
        </button>
      </div>
    </nav>
  );
}
