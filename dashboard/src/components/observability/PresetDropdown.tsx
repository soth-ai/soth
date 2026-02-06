"use client";

import { useState, useRef, useEffect } from "react";
import {
  BookmarkSimple,
  CaretDown,
  Plus,
  Trash,
  Check,
  ShieldWarning,
  Eye,
  Timer,
  XCircle,
  Cpu,
  CloudArrowUp,
  Robot,
  Funnel,
  X,
} from "@phosphor-icons/react";
import { useObservabilityStore, usePresets, type FilterPreset } from "@/store/observability";
import { cn } from "@/lib/utils";

// Icon map for dynamic icon rendering
const iconMap: Record<string, React.ElementType> = {
  ShieldWarning,
  Eye,
  Timer,
  XCircle,
  Cpu,
  CloudArrowUp,
  Robot,
  Funnel,
  BookmarkSimple,
};

const colorClasses: Record<string, string> = {
  red: "bg-red-500/10 text-red-500 border-red-500/30",
  orange: "bg-orange-500/10 text-orange-500 border-orange-500/30",
  amber: "bg-amber-500/10 text-amber-500 border-amber-500/30",
  cyan: "bg-cyan-500/10 text-cyan-500 border-cyan-500/30",
  purple: "bg-purple-500/10 text-purple-500 border-purple-500/30",
  emerald: "bg-emerald-500/10 text-emerald-500 border-emerald-500/30",
  blue: "bg-blue-500/10 text-blue-500 border-blue-500/30",
  gray: "bg-muted text-muted-foreground border-border",
};

export function PresetDropdown() {
  const [isOpen, setIsOpen] = useState(false);
  const [showSaveDialog, setShowSaveDialog] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  const presets = usePresets();
  const filters = useObservabilityStore((state) => state.filters);
  const applyPreset = useObservabilityStore((state) => state.applyPreset);
  const deletePreset = useObservabilityStore((state) => state.deletePreset);

  // Check if any filters are active
  const hasActiveFilters = Object.values(filters).some((v) => v !== undefined);

  // Close dropdown on outside click
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    if (isOpen) {
      document.addEventListener("mousedown", handleClickOutside);
      return () => document.removeEventListener("mousedown", handleClickOutside);
    }
  }, [isOpen]);

  const builtInPresets = presets.filter((p) => p.isBuiltIn);
  const userPresets = presets.filter((p) => !p.isBuiltIn);

  return (
    <div className="relative" ref={dropdownRef}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className={cn(
          "inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-all",
          "bg-transparent text-muted-foreground border-border",
          "hover:bg-muted/50 hover:text-foreground hover:border-border-hover"
        )}
      >
        <BookmarkSimple className="w-3.5 h-3.5" weight="duotone" />
        <span>Presets</span>
        <CaretDown className={cn("w-3 h-3 transition-transform", isOpen && "rotate-180")} />
      </button>

      {isOpen && (
        <div className="absolute top-full mt-1 left-0 w-64 bg-card border border-border rounded-lg shadow-xl z-50 overflow-hidden">
          {/* Built-in Presets */}
          <div className="p-1.5">
            <div className="px-2 py-1.5 text-[10px] font-medium text-muted-foreground uppercase tracking-wider">
              Quick Filters
            </div>
            {builtInPresets.map((preset) => (
              <PresetItem
                key={preset.id}
                preset={preset}
                onApply={() => {
                  applyPreset(preset.id);
                  setIsOpen(false);
                }}
              />
            ))}
          </div>

          {/* Divider */}
          <div className="h-px bg-border" />

          {/* User Presets */}
          <div className="p-1.5">
            <div className="px-2 py-1.5 text-[10px] font-medium text-muted-foreground uppercase tracking-wider flex items-center justify-between">
              <span>Saved Presets</span>
              {hasActiveFilters && (
                <button
                  onClick={() => {
                    setShowSaveDialog(true);
                    setIsOpen(false);
                  }}
                  className="flex items-center gap-1 px-1.5 py-0.5 rounded text-accent hover:bg-accent/10 transition-colors"
                >
                  <Plus className="w-3 h-3" />
                  <span className="text-[10px] normal-case font-normal">Save Current</span>
                </button>
              )}
            </div>

            {userPresets.length === 0 ? (
              <div className="px-2 py-3 text-xs text-muted-foreground text-center">
                No saved presets yet
              </div>
            ) : (
              userPresets.map((preset) => (
                <PresetItem
                  key={preset.id}
                  preset={preset}
                  onApply={() => {
                    applyPreset(preset.id);
                    setIsOpen(false);
                  }}
                  onDelete={() => deletePreset(preset.id)}
                  showDelete
                />
              ))
            )}
          </div>
        </div>
      )}

      {showSaveDialog && (
        <SavePresetDialog onClose={() => setShowSaveDialog(false)} />
      )}
    </div>
  );
}

function PresetItem({
  preset,
  onApply,
  onDelete,
  showDelete,
}: {
  preset: FilterPreset;
  onApply: () => void;
  onDelete?: () => void;
  showDelete?: boolean;
}) {
  const Icon = preset.icon ? iconMap[preset.icon] || BookmarkSimple : BookmarkSimple;
  const color = preset.color || "gray";

  return (
    <div
      className={cn(
        "group flex items-center gap-2 px-2 py-2 rounded-md cursor-pointer transition-colors",
        "hover:bg-muted"
      )}
      onClick={onApply}
    >
      <div
        className={cn(
          "flex items-center justify-center w-6 h-6 rounded border",
          colorClasses[color]
        )}
      >
        <Icon className="w-3.5 h-3.5" weight="duotone" />
      </div>
      <div className="flex-1 min-w-0">
        <div className="text-xs font-medium text-foreground truncate">{preset.name}</div>
        {preset.description && (
          <div className="text-[10px] text-muted-foreground truncate">{preset.description}</div>
        )}
      </div>
      {showDelete && onDelete && (
        <button
          onClick={(e) => {
            e.stopPropagation();
            onDelete();
          }}
          className="opacity-0 group-hover:opacity-100 p-1 rounded hover:bg-destructive/10 hover:text-destructive transition-all"
        >
          <Trash className="w-3.5 h-3.5" />
        </button>
      )}
    </div>
  );
}

function SavePresetDialog({ onClose }: { onClose: () => void }) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [selectedIcon, setSelectedIcon] = useState<string>("Funnel");
  const [selectedColor, setSelectedColor] = useState<FilterPreset["color"]>("blue");

  const savePreset = useObservabilityStore((state) => state.savePreset);
  const filters = useObservabilityStore((state) => state.filters);

  const iconOptions = ["Funnel", "BookmarkSimple", "ShieldWarning", "Eye", "Timer", "XCircle"];
  const colorOptions: FilterPreset["color"][] = ["blue", "purple", "cyan", "emerald", "amber", "orange", "red"];

  // Describe current filters
  const filterDescription = Object.entries(filters)
    .filter(([, value]) => value !== undefined)
    .map(([key]) => key)
    .join(", ");

  const handleSave = () => {
    if (!name.trim()) return;
    savePreset(name.trim(), description.trim() || undefined, selectedIcon, selectedColor);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      <div className="relative bg-card border border-border rounded-xl shadow-2xl w-full max-w-md p-5">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-foreground">Save Filter Preset</h3>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg hover:bg-muted transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Current Filters Summary */}
        <div className="mb-4 p-3 bg-muted/50 rounded-lg border border-border">
          <div className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider mb-1">
            Current Filters
          </div>
          <div className="text-xs text-foreground">
            {filterDescription || "No filters active"}
          </div>
        </div>

        {/* Name Input */}
        <div className="mb-4">
          <label className="block text-xs font-medium text-muted-foreground mb-1.5">
            Name
          </label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g., Production Errors"
            className="w-full px-3 py-2 text-sm bg-background border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-accent/50 focus:border-accent"
            autoFocus
          />
        </div>

        {/* Description Input */}
        <div className="mb-4">
          <label className="block text-xs font-medium text-muted-foreground mb-1.5">
            Description (optional)
          </label>
          <input
            type="text"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="e.g., All error responses from production"
            className="w-full px-3 py-2 text-sm bg-background border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-accent/50 focus:border-accent"
          />
        </div>

        {/* Icon & Color Selection */}
        <div className="mb-5 flex gap-4">
          {/* Icon */}
          <div className="flex-1">
            <label className="block text-xs font-medium text-muted-foreground mb-1.5">
              Icon
            </label>
            <div className="flex gap-1 flex-wrap">
              {iconOptions.map((iconName) => {
                const Icon = iconMap[iconName] || BookmarkSimple;
                return (
                  <button
                    key={iconName}
                    onClick={() => setSelectedIcon(iconName)}
                    className={cn(
                      "p-2 rounded-lg border transition-all",
                      selectedIcon === iconName
                        ? "bg-accent/10 border-accent text-accent"
                        : "border-border text-muted-foreground hover:border-border-hover hover:text-foreground"
                    )}
                  >
                    <Icon className="w-4 h-4" weight={selectedIcon === iconName ? "fill" : "duotone"} />
                  </button>
                );
              })}
            </div>
          </div>

          {/* Color */}
          <div className="flex-1">
            <label className="block text-xs font-medium text-muted-foreground mb-1.5">
              Color
            </label>
            <div className="flex gap-1 flex-wrap">
              {colorOptions.map((color) => (
                <button
                  key={color}
                  onClick={() => setSelectedColor(color)}
                  className={cn(
                    "w-7 h-7 rounded-lg border-2 transition-all flex items-center justify-center",
                    colorClasses[color || "gray"],
                    selectedColor === color ? "ring-2 ring-offset-2 ring-offset-background ring-current" : ""
                  )}
                >
                  {selectedColor === color && <Check className="w-3 h-3" />}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Actions */}
        <div className="flex gap-2 justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm font-medium text-muted-foreground hover:text-foreground rounded-lg hover:bg-muted transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            disabled={!name.trim()}
            className={cn(
              "px-4 py-2 text-sm font-medium rounded-lg transition-colors",
              name.trim()
                ? "bg-accent text-accent-foreground hover:bg-accent/90"
                : "bg-muted text-muted-foreground cursor-not-allowed"
            )}
          >
            Save Preset
          </button>
        </div>
      </div>
    </div>
  );
}
