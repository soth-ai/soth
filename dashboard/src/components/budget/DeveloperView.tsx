"use client";

import {
  ChartPie,
  Coin,
  Wrench,
  Lightning,
  TrendDown,
  CaretDown,
  CaretUp,
  Lightbulb,
  Code,
  ArrowRight,
} from "@phosphor-icons/react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, formatNumber, formatCurrency } from "@/lib/utils";
import type { AdvancedBudgetMetrics } from "@/types";

interface DeveloperViewProps {
  metrics: AdvancedBudgetMetrics | undefined;
  isLoading: boolean;
}

export function DeveloperView({ metrics, isLoading }: DeveloperViewProps) {
  if (isLoading) {
    return <DeveloperViewSkeleton />;
  }

  if (!metrics) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center">
        <div className="h-16 w-16 rounded-2xl bg-muted/50 flex items-center justify-center mb-4">
          <Code className="h-8 w-8 text-muted-foreground" weight="duotone" />
        </div>
        <h3 className="text-lg font-semibold mb-1">No Budget Data</h3>
        <p className="text-sm text-muted-foreground max-w-sm">
          Start making AI API requests to see cost breakdown and optimization recommendations.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Cost by Provider & Model */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <CostByProviderCard providers={metrics.cost_by_provider} />
        <CostByRequestTypeCard requestTypes={metrics.cost_by_request_type} totalCost={metrics.total_cost_usd} />
      </div>

      {/* Cost by MCP Tool */}
      <CostByToolCard tools={metrics.cost_by_tool} />

      {/* Optimization Recommendations */}
      <RecommendationsCard recommendations={metrics.recommendations} />
    </div>
  );
}

function DeveloperViewSkeleton() {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <Card>
          <CardContent className="p-6">
            <Skeleton className="h-64 w-full" />
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-6">
            <Skeleton className="h-64 w-full" />
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardContent className="p-6">
          <Skeleton className="h-48 w-full" />
        </CardContent>
      </Card>
    </div>
  );
}

interface CostByProviderCardProps {
  providers: Record<string, {
    total_cost: number;
    total_tokens: number;
    input_tokens: number;
    output_tokens: number;
    request_count: number;
    model_breakdown: Record<string, {
      model_name: string;
      cost: number;
      input_tokens: number;
      output_tokens: number;
      request_count: number;
      avg_cost_per_request: number;
    }>;
  }>;
}

function CostByProviderCard({ providers }: CostByProviderCardProps) {
  const providerEntries = Object.entries(providers).sort(([, a], [, b]) => b.total_cost - a.total_cost);
  const totalCost = providerEntries.reduce((sum, [, p]) => sum + p.total_cost, 0);

  if (providerEntries.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>
            <ChartPie className="h-4 w-4 text-accent" weight="duotone" />
            Cost by Provider
          </CardTitle>
        </CardHeader>
        <CardContent>
          <EmptyState icon={ChartPie} message="No provider data yet" />
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <ChartPie className="h-4 w-4 text-accent" weight="duotone" />
          Cost by Provider & Model
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {providerEntries.map(([provider, data]) => {
            const percentage = totalCost > 0 ? (data.total_cost / totalCost) * 100 : 0;
            const modelEntries = Object.entries(data.model_breakdown).sort(([, a], [, b]) => b.cost - a.cost);

            return (
              <div key={provider} className="border border-border rounded-lg p-4">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <ProviderIcon provider={provider} />
                    <span className="font-semibold capitalize">{provider}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-muted-foreground">{percentage.toFixed(1)}%</span>
                    <span className="font-bold tabular-nums">{formatCurrency(data.total_cost)}</span>
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-2 mb-3 text-center">
                  <div className="bg-muted/30 rounded p-2">
                    <p className="text-sm font-bold tabular-nums">{formatNumber(data.request_count)}</p>
                    <p className="text-[10px] text-muted-foreground">Requests</p>
                  </div>
                  <div className="bg-cyan-500/10 rounded p-2">
                    <p className="text-sm font-bold tabular-nums text-cyan-500">{formatNumber(data.input_tokens)}</p>
                    <p className="text-[10px] text-muted-foreground">Input</p>
                  </div>
                  <div className="bg-emerald-500/10 rounded p-2">
                    <p className="text-sm font-bold tabular-nums text-emerald-500">{formatNumber(data.output_tokens)}</p>
                    <p className="text-[10px] text-muted-foreground">Output</p>
                  </div>
                </div>

                {modelEntries.length > 0 && (
                  <div className="space-y-2 pt-2 border-t border-border/50">
                    {modelEntries.slice(0, 3).map(([modelId, model]) => (
                      <div key={modelId} className="flex items-center justify-between text-sm">
                        <span className="font-mono text-xs truncate max-w-[150px]" title={model.model_name}>
                          {model.model_name}
                        </span>
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] text-muted-foreground">
                            {formatNumber(model.request_count)} req
                          </span>
                          <span className="font-medium tabular-nums">{formatCurrency(model.cost)}</span>
                        </div>
                      </div>
                    ))}
                    {modelEntries.length > 3 && (
                      <p className="text-xs text-muted-foreground text-center pt-1">
                        +{modelEntries.length - 3} more models
                      </p>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}

interface CostByRequestTypeCardProps {
  requestTypes: Record<string, number>;
  totalCost: number;
}

function CostByRequestTypeCard({ requestTypes, totalCost }: CostByRequestTypeCardProps) {
  const entries = Object.entries(requestTypes).sort(([, a], [, b]) => b - a);
  const maxCost = entries.length > 0 ? entries[0][1] : 0;

  const typeLabels: Record<string, { label: string; color: string }> = {
    ai_inference: { label: "AI Inference", color: "bg-violet-500" },
    mcp_tool_call: { label: "MCP Tool Calls", color: "bg-amber-500" },
    mcp_resource: { label: "MCP Resources", color: "bg-blue-500" },
    mcp_prompt: { label: "MCP Prompts", color: "bg-pink-500" },
  };

  if (entries.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>
            <Lightning className="h-4 w-4 text-accent" weight="duotone" />
            Cost by Request Type
          </CardTitle>
        </CardHeader>
        <CardContent>
          <EmptyState icon={Lightning} message="No request data yet" />
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <Lightning className="h-4 w-4 text-accent" weight="duotone" />
          Cost by Request Type
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {entries.map(([type, cost]) => {
            const percentage = totalCost > 0 ? (cost / totalCost) * 100 : 0;
            const barWidth = maxCost > 0 ? (cost / maxCost) * 100 : 0;
            const typeInfo = typeLabels[type] || { label: type, color: "bg-accent" };

            return (
              <div key={type}>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-sm font-medium">{typeInfo.label}</span>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-muted-foreground tabular-nums">{percentage.toFixed(1)}%</span>
                    <span className="font-bold tabular-nums">{formatCurrency(cost)}</span>
                  </div>
                </div>
                <Progress value={barWidth} className="h-2" indicatorClassName={typeInfo.color} />
              </div>
            );
          })}
        </div>

        {/* Summary pie indicator */}
        <div className="mt-6 pt-4 border-t border-border">
          <div className="flex items-center justify-between">
            <span className="text-sm text-muted-foreground">Total</span>
            <span className="text-lg font-bold tabular-nums">{formatCurrency(totalCost)}</span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

interface CostByToolCardProps {
  tools: Array<{
    tool_name: string;
    server_name: string;
    total_cost: number;
    call_count: number;
    avg_cost_per_call: number;
  }>;
}

function CostByToolCard({ tools }: CostByToolCardProps) {
  const sortedTools = [...tools].sort((a, b) => b.total_cost - a.total_cost);
  const maxCost = sortedTools.length > 0 ? sortedTools[0].total_cost : 0;

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <Wrench className="h-4 w-4 text-accent" weight="duotone" />
          Cost by MCP Tool
        </CardTitle>
      </CardHeader>
      <CardContent>
        {sortedTools.length === 0 ? (
          <EmptyState icon={Wrench} message="No MCP tool usage recorded yet" />
        ) : (
          <div className="space-y-3">
            {sortedTools.slice(0, 10).map((tool, idx) => {
              const barWidth = maxCost > 0 ? (tool.total_cost / maxCost) * 100 : 0;

              return (
                <div key={`${tool.server_name}/${tool.tool_name}`} className="group">
                  <div className="flex items-center gap-3 mb-1">
                    <span className={cn(
                      "w-5 h-5 rounded flex items-center justify-center text-xs font-bold shrink-0",
                      idx === 0 ? "bg-accent text-accent-foreground" : "bg-muted text-muted-foreground"
                    )}>
                      {idx + 1}
                    </span>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-sm font-medium truncate">{tool.tool_name}</span>
                        <span className="text-[10px] text-muted-foreground bg-muted px-1.5 py-0.5 rounded">
                          {tool.server_name}
                        </span>
                      </div>
                    </div>
                    <div className="flex items-center gap-4 shrink-0">
                      <div className="text-right">
                        <span className="text-xs text-muted-foreground block">
                          {formatNumber(tool.call_count)} calls
                        </span>
                        <span className="text-[10px] text-muted-foreground">
                          ~{formatCurrency(tool.avg_cost_per_call)}/call
                        </span>
                      </div>
                      <span className="font-bold tabular-nums min-w-[70px] text-right">
                        {formatCurrency(tool.total_cost)}
                      </span>
                    </div>
                  </div>
                  <Progress value={barWidth} className="h-1.5 ml-8" indicatorClassName="bg-amber-500" />
                </div>
              );
            })}
            {sortedTools.length > 10 && (
              <p className="text-xs text-muted-foreground text-center pt-2">
                +{sortedTools.length - 10} more tools
              </p>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

interface RecommendationsCardProps {
  recommendations: Array<{
    id: string;
    recommendation_type: string;
    title: string;
    description: string;
    estimated_savings: number;
    effort: "low" | "medium" | "high";
  }>;
}

function RecommendationsCard({ recommendations }: RecommendationsCardProps) {
  const effortColors = {
    low: "bg-success/10 text-success border-success/20",
    medium: "bg-warning/10 text-warning border-warning/20",
    high: "bg-destructive/10 text-destructive border-destructive/20",
  };

  const totalSavings = recommendations.reduce((sum, r) => sum + r.estimated_savings, 0);

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <Lightbulb className="h-4 w-4 text-accent" weight="duotone" />
          Optimization Recommendations
          {totalSavings > 0 && (
            <span className="ml-auto text-sm font-normal text-success">
              Potential savings: {formatCurrency(totalSavings)}/day
            </span>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {recommendations.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-8 text-center">
            <div className="h-12 w-12 rounded-xl bg-success/10 flex items-center justify-center mb-3">
              <TrendDown className="h-6 w-6 text-success" weight="duotone" />
            </div>
            <h4 className="font-semibold mb-1">Looking Good!</h4>
            <p className="text-sm text-muted-foreground">
              No immediate optimization opportunities detected.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {recommendations.map((rec) => (
              <div
                key={rec.id}
                className="p-4 border border-border rounded-lg hover:border-accent/50 transition-colors group"
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <h4 className="font-semibold text-sm">{rec.title}</h4>
                      <span className={cn(
                        "text-[10px] px-1.5 py-0.5 rounded border",
                        effortColors[rec.effort]
                      )}>
                        {rec.effort} effort
                      </span>
                    </div>
                    <p className="text-sm text-muted-foreground">{rec.description}</p>
                  </div>
                  <div className="text-right shrink-0">
                    <span className="text-lg font-bold text-success tabular-nums">
                      {formatCurrency(rec.estimated_savings)}
                    </span>
                    <p className="text-[10px] text-muted-foreground">est. savings/day</p>
                  </div>
                </div>
                <button className="mt-3 flex items-center gap-1 text-xs text-accent hover:underline opacity-0 group-hover:opacity-100 transition-opacity">
                  Learn more <ArrowRight className="h-3 w-3" />
                </button>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function EmptyState({ icon: Icon, message }: { icon: React.ElementType; message: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-8 text-center">
      <div className="h-12 w-12 rounded-xl bg-muted/50 flex items-center justify-center mb-3">
        <Icon className="h-6 w-6 text-muted-foreground" weight="duotone" />
      </div>
      <p className="text-sm text-muted-foreground">{message}</p>
    </div>
  );
}

function ProviderIcon({ provider }: { provider: string }) {
  const colors: Record<string, string> = {
    openai: "bg-emerald-500/10 text-emerald-500",
    anthropic: "bg-orange-500/10 text-orange-500",
    google: "bg-blue-500/10 text-blue-500",
  };

  return (
    <div className={cn("w-6 h-6 rounded flex items-center justify-center text-xs font-bold", colors[provider] || "bg-muted text-muted-foreground")}>
      {provider[0]?.toUpperCase()}
    </div>
  );
}
