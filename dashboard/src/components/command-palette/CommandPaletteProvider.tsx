"use client";

import { useEffect } from "react";
import { CommandPalette } from "./CommandPalette";
import { useCommandPalette } from "@/store/command-palette";

export function CommandPaletteProvider() {
  const { isOpen, open, close } = useCommandPalette();

  // Global keyboard shortcut
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // ⌘K or Ctrl+K to open
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        open();
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [open]);

  return <CommandPalette isOpen={isOpen} onClose={close} />;
}
