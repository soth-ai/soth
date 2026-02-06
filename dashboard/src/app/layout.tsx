import type { Metadata, Viewport } from "next";
import { Toaster } from "sonner";
import { Providers } from "@/components/providers";
import { ResponsiveLayout } from "@/components/layout";
import { CommandPaletteProvider } from "@/components/command-palette";
import "./globals.css";

export const metadata: Metadata = {
  title: "SOTH Dashboard",
  description: "AI Control Plane - Real-time metrics & observability",
  appleWebApp: {
    capable: true,
    statusBarStyle: "black-translucent",
    title: "SOTH",
  },
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  maximumScale: 1,
  userScalable: false,
  viewportFit: "cover",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="antialiased min-h-screen bg-background">
        <Providers>
          <ResponsiveLayout>
            {children}
          </ResponsiveLayout>
          <CommandPaletteProvider />
          <Toaster position="top-right" />
        </Providers>
      </body>
    </html>
  );
}
