import type { ScrollSeekConfiguration, ScrollSeekPlaceholderProps } from "react-virtuoso";

export const OBSERVABILITY_SCROLL_SEEK_CONFIG: ScrollSeekConfiguration = {
  // Aggressive thresholds so trackpad fast-scroll enters placeholder mode reliably.
  enter: (velocity) => Math.abs(velocity) > 220,
  exit: (velocity) => Math.abs(velocity) < 45,
};

function ObservabilityScrollSeekPlaceholder({ height }: ScrollSeekPlaceholderProps) {
  const effectiveHeight = Math.max(24, height || 32);

  return (
    <div className="px-4 border-b border-border/60" style={{ height: effectiveHeight }}>
      <div className="flex h-full items-center gap-3">
        <div className="h-2 w-2 rounded-full bg-muted-foreground/25 flex-shrink-0" />
        <div className="h-3 w-24 rounded bg-muted/70 flex-shrink-0" />
        <div className="h-3 w-10 rounded bg-muted/70 flex-shrink-0" />
        <div className="h-4 w-16 rounded-md border border-dashed border-border bg-muted/60 flex-shrink-0" />
        <div className="h-3 flex-1 rounded bg-muted/70" />
        <div className="h-3 w-14 rounded bg-muted/70 flex-shrink-0" />
      </div>
    </div>
  );
}

export const OBSERVABILITY_VIRTUOSO_COMPONENTS = {
  ScrollSeekPlaceholder: ObservabilityScrollSeekPlaceholder,
};
