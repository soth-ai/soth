"use client";

import { useState } from "react";
import {
  Shield,
  CheckCircle,
  XCircle,
  Lightning,
  Clock,
  Funnel,
  ArrowRight,
  Warning,
  WifiSlash,
  Key,
  Fingerprint,
  ShieldCheck,
  Copy,
  Check,
  User,
  CaretDown,
  CaretRight,
} from "@phosphor-icons/react";
import { useDashboardMetrics } from "@/hooks/useDashboardData";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";
import { cn, formatNumber, formatTimestamp } from "@/lib/utils";

// Stat card component
function StatCard({
  label,
  value,
  icon: Icon,
  trend,
  color = "default",
}: {
  label: string;
  value: string | number;
  icon: React.ElementType;
  trend?: string;
  color?: "default" | "success" | "destructive" | "warning";
}) {
  const colorClasses = {
    default: "bg-accent/10 text-accent",
    success: "bg-success/10 text-success",
    destructive: "bg-destructive/10 text-destructive",
    warning: "bg-warning/10 text-warning",
  };

  return (
    <Card>
      <CardContent className="p-6">
        <div className="flex items-start justify-between">
          <div>
            <p className="text-sm text-muted-foreground font-medium">{label}</p>
            <p className="text-3xl font-bold mt-1 tabular-nums">{value}</p>
            {trend && (
              <p className="text-xs text-muted-foreground mt-1">{trend}</p>
            )}
          </div>
          <div className={cn("p-3 rounded-xl", colorClasses[color])}>
            <Icon className="h-6 w-6" weight="duotone" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// DID display with copy functionality
function DidBadge({ did, verified }: { did: string; verified: boolean }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(did);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Truncate DID for display
  const truncatedDid = did.length > 30
    ? `${did.slice(0, 16)}...${did.slice(-8)}`
    : did;

  return (
    <div
      className={cn(
        "flex items-center gap-2 px-3 py-2 rounded-lg border cursor-pointer transition-all hover:bg-muted/50",
        verified
          ? "bg-success/5 border-success/20"
          : "bg-destructive/5 border-destructive/20"
      )}
      onClick={handleCopy}
      title={did}
    >
      <Fingerprint
        className={cn(
          "h-4 w-4",
          verified ? "text-success" : "text-destructive"
        )}
        weight="duotone"
      />
      <code className="text-xs font-mono flex-1 truncate">{truncatedDid}</code>
      {copied ? (
        <Check className="h-3.5 w-3.5 text-success" weight="bold" />
      ) : (
        <Copy className="h-3.5 w-3.5 text-muted-foreground" />
      )}
      <span
        className={cn(
          "text-[10px] font-medium px-1.5 py-0.5 rounded",
          verified
            ? "bg-success/10 text-success"
            : "bg-destructive/10 text-destructive"
        )}
      >
        {verified ? "Verified" : "Unverified"}
      </span>
    </div>
  );
}

export default function PoliciesPage() {
  const { isLoading, isConnected, identity, policy } = useDashboardMetrics();
  const [showAllDids, setShowAllDids] = useState(false);

  const total = (policy?.cache_hits ?? 0) + (policy?.cache_misses ?? 0);
  const cacheHitRate = total > 0 ? ((policy?.cache_hits ?? 0) / total) * 100 : 0;
  const allowRate = (policy?.evaluations ?? 0) > 0
    ? ((policy?.allowed ?? 0) / (policy?.evaluations ?? 1)) * 100
    : 0;

  const verificationRate = (identity?.total_verifications ?? 0) > 0
    ? ((identity?.successful ?? 0) / (identity?.total_verifications ?? 1)) * 100
    : 0;

  const displayedDids = showAllDids
    ? identity?.recent_dids ?? []
    : (identity?.recent_dids ?? []).slice(0, 3);

  return (
    <div className="min-h-screen">
      {/* Page Header */}
      <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-10">
        <div className="px-4 md:px-6 py-3 md:py-4 flex items-center justify-between">
          <div className="flex items-center gap-2 md:gap-3">
            <div className="h-7 w-7 md:h-8 md:w-8 rounded-lg bg-accent/10 flex items-center justify-center">
              <ShieldCheck className="h-4 w-4 md:h-5 md:w-5 text-accent" weight="duotone" />
            </div>
            <div>
              <h1 className="text-base md:text-lg font-semibold">Identity & Policy</h1>
              <p className="text-[10px] md:text-xs text-muted-foreground hidden sm:block">
                DID verification & access control
              </p>
            </div>
          </div>
        </div>
      </header>

      <div className="px-4 md:px-6 py-4 md:py-6">
        {!isConnected && !isLoading && (
          <div className="mb-6 p-4 rounded-lg bg-destructive/10 border border-destructive/20">
            <div className="flex items-center gap-2 text-sm text-destructive">
              <WifiSlash className="h-4 w-4" weight="bold" />
              <span>
                Unable to connect to SOTH backend. Make sure the proxy is running.
              </span>
            </div>
          </div>
        )}

        {/* Identity Section */}
        <section className="mb-6 md:mb-8">
          <div className="flex items-center gap-2 mb-3 md:mb-4">
            <Key className="h-4 w-4 md:h-5 md:w-5 text-accent" weight="duotone" />
            <h2 className="text-base md:text-lg font-semibold">Identity Verification</h2>
          </div>

          {/* Identity Stats */}
          <div className="grid grid-cols-2 md:grid-cols-2 xl:grid-cols-4 gap-3 md:gap-4 mb-4 md:mb-6">
            {isLoading ? (
              <>
                {[...Array(4)].map((_, i) => (
                  <Card key={i}>
                    <CardContent className="p-5">
                      <Skeleton className="h-16 w-full" />
                    </CardContent>
                  </Card>
                ))}
              </>
            ) : (
              <>
                <Card>
                  <CardContent className="p-5">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Unique DIDs</p>
                        <p className="text-2xl font-bold mt-1 tabular-nums">{identity?.unique_dids ?? 0}</p>
                      </div>
                      <div className="p-2.5 rounded-lg bg-accent/10">
                        <Fingerprint className="h-5 w-5 text-accent" weight="duotone" />
                      </div>
                    </div>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="p-5">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Verifications</p>
                        <p className="text-2xl font-bold mt-1 tabular-nums">{identity?.total_verifications ?? 0}</p>
                      </div>
                      <div className="p-2.5 rounded-lg bg-purple-500/10">
                        <ShieldCheck className="h-5 w-5 text-purple-500" weight="duotone" />
                      </div>
                    </div>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="p-5">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Successful</p>
                        <p className="text-2xl font-bold mt-1 tabular-nums text-success">{identity?.successful ?? 0}</p>
                      </div>
                      <div className="p-2.5 rounded-lg bg-success/10">
                        <CheckCircle className="h-5 w-5 text-success" weight="duotone" />
                      </div>
                    </div>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="p-5">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Failed</p>
                        <p className={cn(
                          "text-2xl font-bold mt-1 tabular-nums",
                          (identity?.failed ?? 0) > 0 ? "text-destructive" : "text-muted-foreground"
                        )}>
                          {identity?.failed ?? 0}
                        </p>
                      </div>
                      <div className={cn(
                        "p-2.5 rounded-lg",
                        (identity?.failed ?? 0) > 0 ? "bg-destructive/10" : "bg-muted"
                      )}>
                        <XCircle
                          className={cn(
                            "h-5 w-5",
                            (identity?.failed ?? 0) > 0 ? "text-destructive" : "text-muted-foreground"
                          )}
                          weight="duotone"
                        />
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </>
            )}
          </div>

          {/* Recent DIDs */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <User className="h-4 w-4 text-muted-foreground" weight="duotone" />
                  Recent Identities
                </div>
                <span className="text-xs font-normal text-muted-foreground">
                  {identity?.unique_dids ?? 0} unique
                </span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="space-y-2">
                  {[...Array(3)].map((_, i) => (
                    <Skeleton key={i} className="h-12 w-full" />
                  ))}
                </div>
              ) : (identity?.recent_dids?.length ?? 0) === 0 ? (
                <div className="flex flex-col items-center justify-center py-8 text-center">
                  <div className="h-12 w-12 rounded-xl bg-muted flex items-center justify-center mb-3">
                    <Fingerprint className="h-6 w-6 text-muted-foreground" weight="duotone" />
                  </div>
                  <p className="text-sm text-muted-foreground">No identities recorded yet</p>
                </div>
              ) : (
                <>
                  <div className="space-y-2">
                    {displayedDids.map((entry, i) => (
                      <div key={i} className="flex items-center gap-3">
                        <DidBadge did={entry.did} verified={entry.verified} />
                        <span className="text-xs text-muted-foreground whitespace-nowrap">
                          {formatTimestamp(entry.last_seen)}
                        </span>
                      </div>
                    ))}
                  </div>
                  {(identity?.recent_dids?.length ?? 0) > 3 && (
                    <button
                      onClick={() => setShowAllDids(!showAllDids)}
                      className="mt-3 flex items-center gap-1 text-xs text-accent hover:underline"
                    >
                      {showAllDids ? (
                        <>
                          <CaretDown className="h-3 w-3" />
                          Show less
                        </>
                      ) : (
                        <>
                          <CaretRight className="h-3 w-3" />
                          Show all {identity?.recent_dids?.length}
                        </>
                      )}
                    </button>
                  )}
                </>
              )}
            </CardContent>
          </Card>
        </section>

        {/* Policy Section */}
        <section>
          <div className="flex items-center gap-2 mb-3 md:mb-4">
            <Shield className="h-4 w-4 md:h-5 md:w-5 text-accent" weight="duotone" />
            <h2 className="text-base md:text-lg font-semibold">Policy Enforcement</h2>
          </div>

          {/* Policy Stats Grid */}
          <div className="grid grid-cols-2 md:grid-cols-2 xl:grid-cols-4 gap-3 md:gap-4 mb-4 md:mb-6">
            {isLoading ? (
              <>
                {[...Array(4)].map((_, i) => (
                  <Card key={i}>
                    <CardContent className="p-5">
                      <Skeleton className="h-16 w-full" />
                    </CardContent>
                  </Card>
                ))}
              </>
            ) : (
              <>
                <StatCard
                  label="Total Evaluations"
                  value={formatNumber(policy?.evaluations ?? 0)}
                  icon={Shield}
                  color="default"
                />
                <StatCard
                  label="Allowed"
                  value={formatNumber(policy?.allowed ?? 0)}
                  icon={CheckCircle}
                  trend={`${allowRate.toFixed(1)}% allow rate`}
                  color="success"
                />
                <StatCard
                  label="Denied"
                  value={formatNumber(policy?.denied ?? 0)}
                  icon={XCircle}
                  color={(policy?.denied ?? 0) > 0 ? "destructive" : "default"}
                />
                <StatCard
                  label="Cache Hit Rate"
                  value={`${cacheHitRate.toFixed(1)}%`}
                  icon={Lightning}
                  trend={`${formatNumber(policy?.cache_hits ?? 0)} hits`}
                  color={cacheHitRate >= 80 ? "success" : cacheHitRate >= 50 ? "warning" : "destructive"}
                />
              </>
            )}
          </div>

          {/* Main Content Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 md:gap-6">
            {/* Cache Performance */}
            <Card className="lg:col-span-1">
              <CardHeader>
                <CardTitle>
                  <Lightning className="h-4 w-4 text-accent" weight="duotone" />
                  Cache Performance
                </CardTitle>
              </CardHeader>
              <CardContent>
                {isLoading ? (
                  <div className="space-y-4">
                    <Skeleton className="h-8 w-full" />
                    <Skeleton className="h-20 w-full" />
                  </div>
                ) : (
                  <>
                    <div className="mb-6">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-sm text-muted-foreground">Hit Rate</span>
                        <span className={cn(
                          "text-2xl font-bold tabular-nums",
                          cacheHitRate >= 80 ? "text-success" :
                          cacheHitRate >= 50 ? "text-warning" : "text-destructive"
                        )}>
                          {cacheHitRate.toFixed(1)}%
                        </span>
                      </div>
                      <Progress
                        value={cacheHitRate}
                        className="h-3"
                        indicatorClassName={cn(
                          cacheHitRate >= 80 ? "bg-success" :
                          cacheHitRate >= 50 ? "bg-warning" : "bg-destructive"
                        )}
                      />
                    </div>

                    <div className="space-y-4">
                      <div className="flex items-center justify-between p-3 bg-success/5 border border-success/20 rounded-lg">
                        <div className="flex items-center gap-2">
                          <CheckCircle className="h-4 w-4 text-success" weight="fill" />
                          <span className="text-sm font-medium">Cache Hits</span>
                        </div>
                        <span className="font-bold tabular-nums text-success">
                          {formatNumber(policy?.cache_hits ?? 0)}
                        </span>
                      </div>
                      <div className="flex items-center justify-between p-3 bg-muted/50 border border-border rounded-lg">
                        <div className="flex items-center gap-2">
                          <XCircle className="h-4 w-4 text-muted-foreground" weight="fill" />
                          <span className="text-sm font-medium">Cache Misses</span>
                        </div>
                        <span className="font-bold tabular-nums">
                          {formatNumber(policy?.cache_misses ?? 0)}
                        </span>
                      </div>
                    </div>

                    <div className="mt-6 p-4 bg-muted/30 rounded-lg">
                      <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">
                        Cache Info
                      </h4>
                      <p className="text-xs text-muted-foreground">
                        Policy decisions are cached to improve performance. A high hit rate indicates
                        effective caching of repeated evaluations.
                      </p>
                    </div>
                  </>
                )}
              </CardContent>
            </Card>

            {/* Recent Denials */}
            <Card className="lg:col-span-2">
              <CardHeader>
                <CardTitle>
                  <XCircle className="h-4 w-4 text-destructive" weight="duotone" />
                  Recent Denials
                </CardTitle>
              </CardHeader>
              <CardContent>
                {isLoading ? (
                  <div className="space-y-3">
                    {[...Array(5)].map((_, i) => (
                      <Skeleton key={i} className="h-16 w-full" />
                    ))}
                  </div>
                ) : (policy?.recent_denials?.length ?? 0) === 0 ? (
                  <div className="flex flex-col items-center justify-center py-12 text-center">
                    <div className="h-16 w-16 rounded-2xl bg-success/10 flex items-center justify-center mb-4">
                      <CheckCircle className="h-8 w-8 text-success" weight="duotone" />
                    </div>
                    <h3 className="text-lg font-semibold mb-1">No Recent Denials</h3>
                    <p className="text-sm text-muted-foreground max-w-sm">
                      All policy evaluations have been allowed. Your policies are working as expected.
                    </p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {policy?.recent_denials.map((denial, i) => (
                      <div
                        key={i}
                        className="p-4 bg-destructive/5 border border-destructive/20 rounded-lg hover:bg-destructive/10 transition-colors"
                      >
                        <div className="flex items-start justify-between gap-4">
                          <div className="flex items-start gap-3">
                            <div className="p-2 bg-destructive/10 rounded-lg shrink-0">
                              <XCircle className="h-4 w-4 text-destructive" weight="fill" />
                            </div>
                            <div>
                              <div className="flex items-center gap-2">
                                <span className="font-semibold text-sm">{denial.method}</span>
                                {denial.tool && (
                                  <>
                                    <ArrowRight className="h-3 w-3 text-muted-foreground" />
                                    <code className="text-xs bg-muted px-1.5 py-0.5 rounded font-mono">
                                      {denial.tool}
                                    </code>
                                  </>
                                )}
                              </div>
                              <p className="text-sm text-muted-foreground mt-1">
                                {denial.reason}
                              </p>
                            </div>
                          </div>
                          <div className="flex items-center gap-1.5 text-xs text-muted-foreground shrink-0">
                            <Clock className="h-3 w-3" />
                            {formatTimestamp(denial.timestamp)}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Policy Rules Info */}
          <div className="mt-6 grid grid-cols-1 md:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>
                  <Funnel className="h-4 w-4 text-accent" weight="duotone" />
                  Policy Engine
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="p-4 bg-muted/30 rounded-lg">
                    <h4 className="text-sm font-medium mb-2">OPA Rego Policies</h4>
                    <p className="text-xs text-muted-foreground">
                      SOTH uses the Open Policy Agent (OPA) with Rego policies for flexible,
                      declarative access control. Policies are evaluated in real-time for every request.
                    </p>
                  </div>
                  <div className="flex items-center gap-2 text-sm">
                    <CheckCircle className="h-4 w-4 text-success" weight="fill" />
                    <span>Real-time policy evaluation</span>
                  </div>
                  <div className="flex items-center gap-2 text-sm">
                    <CheckCircle className="h-4 w-4 text-success" weight="fill" />
                    <span>Two-level caching (L1 + L2)</span>
                  </div>
                  <div className="flex items-center gap-2 text-sm">
                    <CheckCircle className="h-4 w-4 text-success" weight="fill" />
                    <span>Identity-aware decisions</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>
                  <Warning className="h-4 w-4 text-warning" weight="duotone" />
                  Enforcement Summary
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">Allow Rate</span>
                    <span className={cn(
                      "text-lg font-bold tabular-nums",
                      allowRate >= 90 ? "text-success" : allowRate >= 70 ? "text-warning" : "text-destructive"
                    )}>
                      {allowRate.toFixed(1)}%
                    </span>
                  </div>
                  <Progress
                    value={allowRate}
                    className="h-2"
                    indicatorClassName={cn(
                      allowRate >= 90 ? "bg-success" :
                      allowRate >= 70 ? "bg-warning" : "bg-destructive"
                    )}
                  />
                  <div className="grid grid-cols-2 gap-4 mt-4">
                    <div className="p-3 bg-success/5 border border-success/20 rounded-lg text-center">
                      <p className="text-2xl font-bold text-success tabular-nums">
                        {formatNumber(policy?.allowed ?? 0)}
                      </p>
                      <p className="text-xs text-muted-foreground">Allowed</p>
                    </div>
                    <div className="p-3 bg-destructive/5 border border-destructive/20 rounded-lg text-center">
                      <p className="text-2xl font-bold text-destructive tabular-nums">
                        {formatNumber(policy?.denied ?? 0)}
                      </p>
                      <p className="text-xs text-muted-foreground">Denied</p>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </section>
      </div>
    </div>
  );
}
