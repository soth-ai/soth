"use client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState, useEffect } from "react";
import { useSettingsStore } from "@/store/settings";
import { ThemeProvider } from "@/components/providers/ThemeProvider";
import { KeyboardShortcuts } from "@/components/providers/KeyboardShortcuts";
import { NotificationProvider } from "@/components/providers/NotificationProvider";

export function Providers({ children }: { children: React.ReactNode }) {
  const refreshInterval = useSettingsStore((state) => state.refreshInterval);

  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            staleTime: 1000, // 1 second
            refetchInterval: refreshInterval,
          },
        },
      })
  );

  // Update query client when refresh interval changes
  useEffect(() => {
    queryClient.setDefaultOptions({
      queries: {
        staleTime: 1000,
        refetchInterval: refreshInterval,
      },
    });
  }, [queryClient, refreshInterval]);

  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <KeyboardShortcuts>
          <NotificationProvider>{children}</NotificationProvider>
        </KeyboardShortcuts>
      </ThemeProvider>
    </QueryClientProvider>
  );
}
