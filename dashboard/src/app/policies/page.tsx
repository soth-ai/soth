"use client";

import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import {
  ShieldCheck,
  WifiSlash,
  CheckCircle,
  XCircle,
  Lightning,
  MagnifyingGlass,
  Plus,
  Copy,
  FileCode,
  Sliders,
  Stack,
  Warning,
} from "@phosphor-icons/react";
import { useBudgetPrimitives, useDashboardMetrics } from "@/hooks/useDashboardData";
import type { BudgetRequestPrimitive } from "@/types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";
import { cn, formatNumber, formatTimestamp } from "@/lib/utils";

type PolicyScope = "global" | "organization" | "agent";
type PolicyIntent = "allow" | "block" | "limit";
type WizardTarget = "all" | "endpoint" | "tool";
type WizardAction = "allow" | "deny" | "rate_limit" | "log";
type WizardExecutionMode = "enforce" | "dry_run";
type ArtifactView = "summary" | "policy-data" | "rego";

interface RateLimitDraft {
  id: string;
  tool: string;
  requests_per_minute: number;
}

interface PolicyDraft {
  id: string;
  name: string;
  description: string;
  scope: PolicyScope;
  priority: number;
  enabled: boolean;
  blocked_tools_text: string;
  blocked_agents_text: string;
  blocked_dids_text: string;
  allowed_dids_text: string;
  trusted_publishers_text: string;
  identity_required_tools_text: string;
  pii_tools_text: string;
  blocked_models_for_pii_text: string;
  rate_limits: RateLimitDraft[];
}

interface RuntimePolicyData {
  tool_capabilities: Record<string, string>;
  rate_limits: Record<string, number>;
  blocked_tools: string[];
  blocked_agents: string[];
  blocked_dids: string[];
  allowed_dids: string[];
  trusted_publishers: string[];
  identity_required_tools: string[];
  pii_tools: string[];
  blocked_models_for_pii: string[];
}

interface WizardState {
  intent: PolicyIntent;
  name: string;
  description: string;
  scope: PolicyScope;
  trafficApi: boolean;
  trafficTools: boolean;
  target: WizardTarget;
  endpointPattern: string;
  toolName: string;
  anyModel: boolean;
  model: string;
  costEnabled: boolean;
  costThreshold: number;
  rateEnabled: boolean;
  rateThreshold: number;
  piiEnabled: boolean;
  metadataEnabled: boolean;
  metadataQuery: string;
  action: WizardAction;
  reason: string;
  emitAlert: boolean;
  recordCostAvoided: boolean;
  executionMode: WizardExecutionMode;
}

interface ImpactPreview {
  matchedRequests: BudgetRequestPrimitive[];
  affectedCount: number;
  affectedPct: number;
  estimatedMonthlySavingsUsd: number;
  highCostBlockedCalls: number;
  notes: string[];
  sampleRequests: BudgetRequestPrimitive[];
}

const WIZARD_STEPS = [
  { id: "intent", label: "Intent" },
  { id: "scope", label: "Scope" },
  { id: "conditions", label: "Conditions" },
  { id: "action", label: "Action" },
  { id: "impact", label: "Impact" },
  { id: "review", label: "Review" },
] as const;

type WizardStepId = (typeof WIZARD_STEPS)[number]["id"];

const FIELD_CLASS =
  "h-8 text-[12px] bg-muted/35 border-border/80 focus-visible:ring-1 focus-visible:ring-accent/35";
const SEARCH_FIELD_CLASS =
  "h-8 pl-8 text-[12px] bg-muted/35 border-border/80 focus-visible:ring-1 focus-visible:ring-accent/35";
const CODE_AREA_CLASS =
  "w-full h-64 rounded-md border border-border/80 bg-muted/25 p-2.5 font-mono text-[11px] leading-5 text-foreground";

const INTENT_PRESETS: Array<{ id: string; label: string; intent: PolicyIntent; description: string }> = [
  {
    id: "block-out-of-scope-tool",
    label: "Block tool outside scope",
    intent: "block",
    description: "Deny risky tool calls not intended for production usage.",
  },
  {
    id: "restrict-models-prod",
    label: "Restrict models in production",
    intent: "block",
    description: "Prevent high-risk or high-cost model usage in production scope.",
  },
  {
    id: "rate-limit-high-cost-endpoint",
    label: "Rate-limit high-cost endpoint",
    intent: "limit",
    description: "Constrain expensive paths to avoid runaway spend or abuse.",
  },
  {
    id: "enforce-cost-guardrail",
    label: "Enforce cost guardrail",
    intent: "limit",
    description: "Keep spend under predictable bounds using threshold-based checks.",
  },
];

function makeId(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

function splitCsv(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function toRuntimePolicyData(policy: PolicyDraft): RuntimePolicyData {
  const rate_limits = Object.fromEntries(
    policy.rate_limits
      .filter((entry) => entry.tool.trim().length > 0 && entry.requests_per_minute > 0)
      .map((entry) => [entry.tool.trim(), entry.requests_per_minute])
  );

  return {
    tool_capabilities: {},
    rate_limits,
    blocked_tools: splitCsv(policy.blocked_tools_text),
    blocked_agents: splitCsv(policy.blocked_agents_text),
    blocked_dids: splitCsv(policy.blocked_dids_text),
    allowed_dids: splitCsv(policy.allowed_dids_text),
    trusted_publishers: splitCsv(policy.trusted_publishers_text),
    identity_required_tools: splitCsv(policy.identity_required_tools_text),
    pii_tools: splitCsv(policy.pii_tools_text),
    blocked_models_for_pii: splitCsv(policy.blocked_models_for_pii_text),
  };
}

function buildRegoScaffold(policy: PolicyDraft, data: RuntimePolicyData): string {
  const blockedTools = data.blocked_tools;
  const blockedAgents = data.blocked_agents;
  const blockedDids = data.blocked_dids;
  const allowedDids = data.allowed_dids;
  const identityRequiredTools = data.identity_required_tools;

  const toRegoArray = (items: string[]): string =>
    `[${items.map((item) => `"${item}"`).join(", ")}]`;

  return `package mcp.policy

import rego.v1

# NOTE:
# Current SOTH runtime enforces policy_data (JSON/YAML) directly.
# This Rego scaffold is for authoring parity and future runtime support.

default allow := true

blocked_tools := ${toRegoArray(blockedTools)}
blocked_agents := ${toRegoArray(blockedAgents)}
blocked_dids := ${toRegoArray(blockedDids)}
allowed_dids := ${toRegoArray(allowedDids)}
identity_required_tools := ${toRegoArray(identityRequiredTools)}

deny[msg] if {
  input.request.tool in blocked_tools
  msg := sprintf("tool '%s' is blocked by policy '${policy.name}'", [input.request.tool])
}

deny[msg] if {
  input.agent.id in blocked_agents
  msg := sprintf("agent '%s' is blocked by policy '${policy.name}'", [input.agent.id])
}

deny[msg] if {
  input.identity.did in blocked_dids
  msg := sprintf("DID '%s' is blocked by policy '${policy.name}'", [input.identity.did])
}

deny[msg] if {
  count(allowed_dids) > 0
  not input.identity.did in allowed_dids
  msg := "identity required (allowed_dids policy)"
}

deny[msg] if {
  input.request.tool in identity_required_tools
  not input.identity.verified
  msg := sprintf("tool '%s' requires verified identity", [input.request.tool])
}

allow if count(deny) == 0
`;
}

function scopeClass(scope: PolicyScope): string {
  if (scope === "global") return "bg-accent/12 text-accent border-accent/25";
  if (scope === "organization") return "bg-warning/12 text-warning border-warning/25";
  return "bg-success/12 text-success border-success/25";
}

function inferToolRequest(request: BudgetRequestPrimitive): boolean {
  const path = request.path.toLowerCase();
  const host = request.host.toLowerCase();
  return (
    path.includes("tools/") ||
    path.includes("/mcp") ||
    path.includes("/tool") ||
    host.includes("mcp")
  );
}

function wildcardMatch(value: string, pattern: string): boolean {
  const source = value.toLowerCase();
  const rule = pattern.trim().toLowerCase();
  if (!rule) return false;
  if (!rule.includes("*")) {
    return source === rule;
  }
  const escaped = rule.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  try {
    return new RegExp(`^${escaped}$`).test(source);
  } catch {
    return source.includes(rule.replaceAll("*", ""));
  }
}

function minuteBucket(timestamp: string): string {
  const date = new Date(timestamp);
  const year = date.getUTCFullYear();
  const month = `${date.getUTCMonth() + 1}`.padStart(2, "0");
  const day = `${date.getUTCDate()}`.padStart(2, "0");
  const hour = `${date.getUTCHours()}`.padStart(2, "0");
  const minute = `${date.getUTCMinutes()}`.padStart(2, "0");
  return `${year}-${month}-${day}T${hour}:${minute}`;
}

function toFixedMoney(value: number): string {
  return `$${value.toFixed(2)}`;
}

function defaultWizardState(): WizardState {
  return {
    intent: "block",
    name: "",
    description: "",
    scope: "organization",
    trafficApi: true,
    trafficTools: false,
    target: "endpoint",
    endpointPattern: "/backend-api/*",
    toolName: "",
    anyModel: true,
    model: "",
    costEnabled: false,
    costThreshold: 0.01,
    rateEnabled: false,
    rateThreshold: 100,
    piiEnabled: false,
    metadataEnabled: false,
    metadataQuery: "",
    action: "deny",
    reason: "Policy condition matched",
    emitAlert: true,
    recordCostAvoided: true,
    executionMode: "dry_run",
  };
}

function buildWizardSeed(searchParams: { get(name: string): string | null }): Partial<WizardState> {
  const endpoint = searchParams.get("endpoint");
  const tool = searchParams.get("tool");
  const model = searchParams.get("model");
  const intent = searchParams.get("intent");
  const reason = searchParams.get("reason");

  const seed: Partial<WizardState> = {};

  if (intent === "allow" || intent === "block" || intent === "limit") {
    seed.intent = intent;
  }

  if (endpoint) {
    seed.target = "endpoint";
    seed.endpointPattern = endpoint;
    seed.name = "Policy from incident";
  }

  if (tool) {
    seed.target = "tool";
    seed.toolName = tool;
    seed.trafficTools = true;
    seed.name = "Tool control policy";
  }

  if (model) {
    seed.anyModel = false;
    seed.model = model;
  }

  if (reason) {
    seed.reason = reason;
  }

  return seed;
}

function applyIntentPreset(current: WizardState, presetId: string): WizardState {
  if (presetId === "block-out-of-scope-tool") {
    return {
      ...current,
      intent: "block",
      target: "tool",
      trafficApi: false,
      trafficTools: true,
      action: "deny",
      reason: "Tool not allowed in this context",
    };
  }
  if (presetId === "restrict-models-prod") {
    return {
      ...current,
      intent: "block",
      target: "endpoint",
      endpointPattern: "/backend-api/*",
      anyModel: false,
      action: "deny",
      reason: "Model not allowed in production",
    };
  }
  if (presetId === "rate-limit-high-cost-endpoint") {
    return {
      ...current,
      intent: "limit",
      target: "endpoint",
      endpointPattern: "/backend-api/*",
      rateEnabled: true,
      rateThreshold: 100,
      action: "rate_limit",
      reason: "High-cost endpoint rate-limited",
    };
  }
  return {
    ...current,
    intent: "limit",
    costEnabled: true,
    costThreshold: 0.01,
    action: "rate_limit",
    reason: "Cost guardrail exceeded",
  };
}

function wizardToPolicyDraft(wizard: WizardState, enabled: boolean): PolicyDraft {
  const blockedTools: string[] = [];
  const identityRequiredTools: string[] = [];
  const piiTools: string[] = [];
  const blockedModelsForPii: string[] = [];
  const rateLimits: RateLimitDraft[] = [];

  const resolvedTool = wizard.toolName.trim();

  if ((wizard.intent === "block" || wizard.action === "deny") && resolvedTool) {
    blockedTools.push(resolvedTool);
  }

  if ((wizard.intent === "limit" || wizard.action === "rate_limit") && resolvedTool) {
    rateLimits.push({
      id: makeId("rl"),
      tool: resolvedTool,
      requests_per_minute: Math.max(1, Math.round(wizard.rateThreshold)),
    });
  }

  if (wizard.piiEnabled && resolvedTool) {
    piiTools.push(resolvedTool);
    identityRequiredTools.push(resolvedTool);
    if (!wizard.anyModel && wizard.model.trim()) {
      blockedModelsForPii.push(wizard.model.trim());
    }
  }

  const contextSummary = [
    wizard.target === "endpoint" && wizard.endpointPattern.trim()
      ? `endpoint=${wizard.endpointPattern.trim()}`
      : null,
    wizard.target === "tool" && resolvedTool ? `tool=${resolvedTool}` : null,
    !wizard.anyModel && wizard.model.trim() ? `model=${wizard.model.trim()}` : null,
    wizard.costEnabled ? `cost>${wizard.costThreshold}` : null,
    wizard.rateEnabled ? `rate>${wizard.rateThreshold}/min` : null,
  ]
    .filter(Boolean)
    .join(", ");

  const descriptionBase = wizard.description.trim()
    ? wizard.description.trim()
    : `${wizard.intent} policy generated via guided wizard`;

  const description = contextSummary
    ? `${descriptionBase} [${contextSummary}]`
    : descriptionBase;

  return {
    id: makeId("policy"),
    name: wizard.name.trim() || "New Policy",
    description,
    scope: wizard.scope,
    priority: wizard.intent === "block" ? 50 : wizard.intent === "limit" ? 100 : 200,
    enabled,
    blocked_tools_text: blockedTools.join(", "),
    blocked_agents_text: "",
    blocked_dids_text: "",
    allowed_dids_text: "",
    trusted_publishers_text: "",
    identity_required_tools_text: identityRequiredTools.join(", "),
    pii_tools_text: piiTools.join(", "),
    blocked_models_for_pii_text: blockedModelsForPii.join(", "),
    rate_limits: rateLimits,
  };
}

function buildRuntimeGapWarnings(wizard: WizardState): string[] {
  const warnings: string[] = [];

  if (wizard.target === "endpoint") {
    warnings.push(
      "Endpoint-scoped controls are not directly representable in current policy_data runtime (tool/DID/capability primitives only)."
    );
  }

  if (!wizard.anyModel && !wizard.piiEnabled) {
    warnings.push(
      "General model restrictions are not directly enforceable in current policy_data unless tied to pii_tools + blocked_models_for_pii."
    );
  }

  if (wizard.costEnabled) {
    warnings.push("Cost-threshold conditions require richer runtime inputs than current policy_data supports.");
  }

  if (wizard.metadataEnabled) {
    warnings.push("Metadata expression matching is not wired into current policy_data primitives.");
  }

  if (wizard.executionMode === "dry_run") {
    warnings.push(
      "Per-policy dry-run is approximated by saving disabled draft; runtime dry-run today is controlled at global policy mode (audit)."
    );
  }

  return warnings;
}

function computeImpactPreview(
  wizard: WizardState,
  requests: BudgetRequestPrimitive[],
  totalReferenceCount: number
): ImpactPreview {
  const notes: string[] = [];

  let matched = requests.filter((request) => {
    const isTool = inferToolRequest(request);

    const matchesTraffic =
      (wizard.trafficApi && !isTool) ||
      (wizard.trafficTools && isTool) ||
      (wizard.trafficApi && wizard.trafficTools);

    if (!matchesTraffic) return false;

    if (wizard.target === "endpoint" && wizard.endpointPattern.trim()) {
      if (!wildcardMatch(request.path, wizard.endpointPattern)) return false;
    }

    if (wizard.target === "tool" && wizard.toolName.trim()) {
      const toolToken = wizard.toolName.trim().toLowerCase();
      const path = request.path.toLowerCase();
      if (!path.includes(toolToken)) return false;
    }

    if (!wizard.anyModel && wizard.model.trim()) {
      if ((request.model ?? "").toLowerCase() !== wizard.model.trim().toLowerCase()) {
        return false;
      }
    }

    if (wizard.costEnabled && (request.cost_usd ?? 0) <= wizard.costThreshold) {
      return false;
    }

    if (wizard.metadataEnabled && wizard.metadataQuery.trim()) {
      const q = wizard.metadataQuery.trim().toLowerCase();
      const searchable = `${request.host} ${request.path} ${request.method} ${request.model ?? ""}`.toLowerCase();
      if (!searchable.includes(q)) {
        return false;
      }
    }

    return true;
  });

  if (wizard.rateEnabled) {
    const buckets = new Map<string, number>();
    for (const req of matched) {
      const key = minuteBucket(req.timestamp);
      buckets.set(key, (buckets.get(key) ?? 0) + 1);
    }
    matched = matched.filter((req) => (buckets.get(minuteBucket(req.timestamp)) ?? 0) > wizard.rateThreshold);
  }

  if (wizard.piiEnabled) {
    notes.push(
      "PII condition is included in policy intent but impact estimate cannot isolate per-request PII from current budget primitives."
    );
  }

  const affectedCount = matched.length;
  const referenceCount = Math.max(1, totalReferenceCount);
  const affectedPct = (affectedCount / referenceCount) * 100;

  const totalMatchedCost = matched.reduce((sum, req) => sum + (req.cost_usd ?? 0), 0);
  const estimatedMonthlySavingsUsd = totalMatchedCost * 30;
  const highCostBlockedCalls = matched.filter((req) => (req.cost_usd ?? 0) >= Math.max(wizard.costThreshold, 0.01)).length;

  const sampleRequests = [...matched]
    .sort((a, b) => (b.cost_usd ?? 0) - (a.cost_usd ?? 0))
    .slice(0, 5);

  if (wizard.action === "allow" || wizard.action === "log") {
    notes.push("Savings estimate shown for visibility; action mode may not directly reduce spend.");
  }

  return {
    matchedRequests: matched,
    affectedCount,
    affectedPct,
    estimatedMonthlySavingsUsd,
    highCostBlockedCalls,
    notes,
    sampleRequests,
  };
}

const POLICY_TEMPLATES: PolicyDraft[] = [
  {
    id: "default",
    name: "Default Safety Policy",
    description: "Balanced baseline for tool blocking, identity checks, and rate limits.",
    scope: "organization",
    priority: 100,
    enabled: true,
    blocked_tools_text: "shell_exec, system_command, exec, eval, run_command",
    blocked_agents_text: "",
    blocked_dids_text: "",
    allowed_dids_text: "",
    trusted_publishers_text: "",
    identity_required_tools_text: "write_file, delete_file, update_file",
    pii_tools_text: "",
    blocked_models_for_pii_text: "",
    rate_limits: [{ id: makeId("rl"), tool: "tools/call", requests_per_minute: 100 }],
  },
  {
    id: "strict",
    name: "Strict Identity-First Policy",
    description: "Fail-safe profile with strong identity gating and conservative limits.",
    scope: "global",
    priority: 10,
    enabled: true,
    blocked_tools_text: "shell_exec, eval, run_command, http_fetch, curl, wget",
    blocked_agents_text: "",
    blocked_dids_text: "",
    allowed_dids_text: "",
    trusted_publishers_text: "",
    identity_required_tools_text: "tools/call, resources/read, sampling/createMessage",
    pii_tools_text: "tools/call",
    blocked_models_for_pii_text: "gpt-4o-mini, claude-haiku",
    rate_limits: [{ id: makeId("rl"), tool: "tools/call", requests_per_minute: 20 }],
  },
  {
    id: "development",
    name: "Development Policy",
    description: "Permissive profile with minimal hard blocks for local testing.",
    scope: "agent",
    priority: 300,
    enabled: false,
    blocked_tools_text: "format_disk, rm_rf, drop_all_databases",
    blocked_agents_text: "",
    blocked_dids_text: "",
    allowed_dids_text: "",
    trusted_publishers_text: "",
    identity_required_tools_text: "",
    pii_tools_text: "",
    blocked_models_for_pii_text: "",
    rate_limits: [],
  },
];

function StatCard({
  title,
  value,
  subtitle,
  icon: Icon,
  tone = "default",
}: {
  title: string;
  value: string;
  subtitle: string;
  icon: React.ElementType;
  tone?: "default" | "success" | "warning" | "destructive";
}) {
  const toneClass =
    tone === "success"
      ? "bg-success/10 text-success"
      : tone === "warning"
      ? "bg-warning/10 text-warning"
      : tone === "destructive"
      ? "bg-destructive/10 text-destructive"
      : "bg-accent/10 text-accent";

  return (
    <Card>
      <CardContent className="p-3.5 md:p-4">
        <div className="flex items-start justify-between gap-3">
          <div>
            <p className="text-[10px] uppercase tracking-[0.08em] text-muted-foreground">{title}</p>
            <p className="mt-1 text-lg font-semibold tabular-nums">{value}</p>
            <p className="mt-1 text-[11px] text-muted-foreground">{subtitle}</p>
          </div>
          <div className={cn("rounded-md p-2", toneClass)}>
            <Icon className="h-4 w-4" weight="duotone" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export default function PoliciesPage() {
  const searchParams = useSearchParams();
  const searchParamsKey = searchParams.toString();
  const { isLoading, isConnected, identity, policy } = useDashboardMetrics();
  const budgetPrimitives = useBudgetPrimitives();

  const [search, setSearch] = useState("");
  const [policies, setPolicies] = useState<PolicyDraft[]>(POLICY_TEMPLATES);
  const [selectedId, setSelectedId] = useState(POLICY_TEMPLATES[0]?.id ?? "");
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [artifactView, setArtifactView] = useState<ArtifactView>("summary");
  const [wizardStepIndex, setWizardStepIndex] = useState(0);
  const [confirmAllTraffic, setConfirmAllTraffic] = useState(false);
  const [lastCreatedPolicyId, setLastCreatedPolicyId] = useState<string | null>(null);

  const initialWizardSeed = useMemo(
    () => buildWizardSeed(new URLSearchParams(searchParamsKey)),
    [searchParamsKey]
  );
  const [wizard, setWizard] = useState<WizardState>({
    ...defaultWizardState(),
    ...initialWizardSeed,
  });

  useEffect(() => {
    if (Object.keys(initialWizardSeed).length === 0) {
      return;
    }
    setWizard((current) => ({ ...current, ...initialWizardSeed }));
  }, [searchParamsKey, initialWizardSeed]);

  const selectedPolicy = useMemo(
    () => policies.find((policyItem) => policyItem.id === selectedId) ?? policies[0] ?? null,
    [policies, selectedId]
  );

  const filteredPolicies = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return policies;
    return policies.filter(
      (policyItem) =>
        policyItem.name.toLowerCase().includes(query) ||
        policyItem.description.toLowerCase().includes(query)
    );
  }, [policies, search]);

  const totalCache = (policy?.cache_hits ?? 0) + (policy?.cache_misses ?? 0);
  const cacheHitRate = totalCache > 0 ? ((policy?.cache_hits ?? 0) / totalCache) * 100 : 0;
  const allowRate =
    (policy?.evaluations ?? 0) > 0
      ? ((policy?.allowed ?? 0) / Math.max(1, policy?.evaluations ?? 1)) * 100
      : 100;
  const identityFailureRate =
    (identity?.total_verifications ?? 0) > 0
      ? ((identity?.failed ?? 0) / Math.max(1, identity?.total_verifications ?? 1)) * 100
      : 0;

  const runtimePolicyData = useMemo(
    () => (selectedPolicy ? toRuntimePolicyData(selectedPolicy) : null),
    [selectedPolicy]
  );

  const policyDataJson = useMemo(
    () => (runtimePolicyData ? JSON.stringify(runtimePolicyData, null, 2) : ""),
    [runtimePolicyData]
  );

  const regoScaffold = useMemo(
    () => (selectedPolicy && runtimePolicyData ? buildRegoScaffold(selectedPolicy, runtimePolicyData) : ""),
    [selectedPolicy, runtimePolicyData]
  );

  const applyGuide = useMemo(() => {
    if (!selectedPolicy) return "";

    const modeHint = selectedPolicy.enabled ? "enforce" : "audit";
    return [
      "1. Save the generated policy_data JSON to a file (example: policies/generated_policy_data.json).",
      "2. In soth.yaml set:",
      "   policy:",
      "     enabled: true",
      `     mode: ${modeHint}`,
      "     data_file: ./policies/generated_policy_data.json",
      "     watch_for_changes: true",
      "3. Restart `soth proxy start` or keep watch mode enabled for hot reload.",
      "4. Validate behavior in Observability using denied/allowed events and policy reasons.",
    ].join("\n");
  }, [selectedPolicy]);

  const recentRequests = useMemo(
    () => budgetPrimitives.data?.data.recent_requests ?? [],
    [budgetPrimitives.data?.data.recent_requests]
  );
  const impactPreview = useMemo(
    () => computeImpactPreview(wizard, recentRequests, recentRequests.length),
    [wizard, recentRequests]
  );

  const runtimeGapWarnings = useMemo(() => buildRuntimeGapWarnings(wizard), [wizard]);

  const step = WIZARD_STEPS[wizardStepIndex];

  const copyText = async (key: string, content: string) => {
    try {
      await navigator.clipboard.writeText(content);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 1800);
    } catch {
      setCopiedKey(null);
    }
  };

  const resetWizard = () => {
    setWizard({
      ...defaultWizardState(),
      ...buildWizardSeed(searchParams),
    });
    setWizardStepIndex(0);
    setConfirmAllTraffic(false);
  };

  const isStepValid = (stepId: WizardStepId): boolean => {
    if (stepId === "intent") {
      return wizard.name.trim().length > 2;
    }
    if (stepId === "scope") {
      if (!wizard.trafficApi && !wizard.trafficTools) return false;
      if (wizard.target === "endpoint") return wizard.endpointPattern.trim().length > 0;
      if (wizard.target === "tool") return wizard.toolName.trim().length > 0;
      return true;
    }
    if (stepId === "conditions") {
      if (!wizard.anyModel && wizard.model.trim().length === 0) return false;
      if (wizard.costEnabled && wizard.costThreshold <= 0) return false;
      if (wizard.rateEnabled && wizard.rateThreshold <= 0) return false;
      return true;
    }
    if (stepId === "action") {
      if ((wizard.action === "deny" || wizard.action === "rate_limit") && wizard.reason.trim().length < 4) {
        return false;
      }
      return true;
    }
    if (stepId === "impact") {
      return true;
    }
    if (stepId === "review") {
      if (wizard.target === "all" && !confirmAllTraffic) {
        return false;
      }
      return true;
    }
    return true;
  };

  const goNext = () => {
    if (!isStepValid(step.id)) return;
    setWizardStepIndex((current) => Math.min(current + 1, WIZARD_STEPS.length - 1));
  };

  const goBack = () => {
    setWizardStepIndex((current) => Math.max(current - 1, 0));
  };

  const createPolicy = (saveAsDraft: boolean) => {
    const shouldEnable = !saveAsDraft && wizard.executionMode === "enforce";
    const generated = wizardToPolicyDraft(wizard, shouldEnable);

    setPolicies((current) => [generated, ...current]);
    setSelectedId(generated.id);
    setLastCreatedPolicyId(generated.id);
    setArtifactView("policy-data");
    setWizardStepIndex(0);
    setConfirmAllTraffic(false);
  };

  return (
    <div className="min-h-screen">
      <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-10">
        <div className="px-4 md:px-6 py-2.5 md:py-3">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <div className="h-7 w-7 rounded-md bg-accent/12 border border-accent/25 flex items-center justify-center">
                <ShieldCheck className="h-4 w-4 text-accent" weight="duotone" />
              </div>
              <div>
                <h1 className="text-base md:text-lg font-semibold">Policy Control Plane</h1>
                <p className="text-[10px] md:text-[11px] text-muted-foreground">
                  Guided enforcement wizard with impact preview and runtime-safe policy generation
                </p>
              </div>
            </div>
            <div className="text-[10px] md:text-[11px] text-muted-foreground">
              Active version: {policy?.active_version ?? "-"}
            </div>
          </div>
        </div>
      </header>

      <div className="px-4 md:px-6 py-4 md:py-5 space-y-4">
        {!isConnected && !isLoading && (
          <div className="p-3 rounded-lg border border-destructive/25 bg-destructive/10">
            <div className="flex items-center gap-2 text-xs text-destructive">
              <WifiSlash className="h-4 w-4" weight="bold" />
              Unable to connect to SOTH backend. Start proxy with dashboard enabled.
            </div>
          </div>
        )}

        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          {isLoading ? (
            Array.from({ length: 4 }).map((_, index) => (
              <Card key={index}>
                <CardContent className="p-3.5">
                  <Skeleton className="h-14 w-full" />
                </CardContent>
              </Card>
            ))
          ) : (
            <>
              <StatCard
                title="Evaluations"
                value={formatNumber(policy?.evaluations ?? 0)}
                subtitle="Total policy checks"
                icon={ShieldCheck}
              />
              <StatCard
                title="Allowed"
                value={`${allowRate.toFixed(1)}%`}
                subtitle={`${formatNumber(policy?.allowed ?? 0)} allowed`}
                icon={CheckCircle}
                tone={allowRate >= 90 ? "success" : allowRate >= 70 ? "warning" : "destructive"}
              />
              <StatCard
                title="Denied"
                value={formatNumber(policy?.denied ?? 0)}
                subtitle="Hard blocks"
                icon={XCircle}
                tone={(policy?.denied ?? 0) > 0 ? "warning" : "default"}
              />
              <StatCard
                title="Cache Hit"
                value={`${cacheHitRate.toFixed(1)}%`}
                subtitle={`${formatNumber(policy?.cache_hits ?? 0)} hits / ${formatNumber(totalCache)}`}
                icon={Lightning}
                tone={cacheHitRate >= 80 ? "success" : cacheHitRate >= 50 ? "warning" : "destructive"}
              />
            </>
          )}
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">
          <Card className="xl:col-span-4">
            <CardHeader>
              <CardTitle className="text-sm font-semibold tracking-[0.02em]">
                <Stack className="h-3.5 w-3.5 text-accent" weight="duotone" />
                Policy Catalog
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex items-center gap-2">
                <div className="relative flex-1">
                  <MagnifyingGlass className="h-3.5 w-3.5 text-muted-foreground absolute left-2.5 top-1/2 -translate-y-1/2" />
                  <Input
                    value={search}
                    onChange={(event) => setSearch(event.target.value)}
                    placeholder="Search policies..."
                    className={SEARCH_FIELD_CLASS}
                  />
                </div>
                <Button size="sm" className="h-8 px-2.5 text-[11px]" onClick={resetWizard}>
                  <Plus className="h-3.5 w-3.5 mr-1" />
                  Create
                </Button>
              </div>

              <div className="border border-border rounded-md overflow-hidden">
                {filteredPolicies.length === 0 ? (
                  <div className="p-4 text-center text-[12px] text-muted-foreground">
                    No policies match your search.
                  </div>
                ) : (
                  filteredPolicies.map((policyItem) => {
                    const selected = selectedPolicy?.id === policyItem.id;
                    return (
                      <button
                        key={policyItem.id}
                        className={cn(
                          "w-full text-left px-3 py-2.5 border-b last:border-b-0 transition-colors",
                          selected ? "bg-accent/10 border-accent/20" : "hover:bg-muted/35"
                        )}
                        onClick={() => setSelectedId(policyItem.id)}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-[12px] font-medium truncate">{policyItem.name}</span>
                          <span
                            className={cn(
                              "text-[10px] px-1.5 py-0.5 rounded border capitalize",
                              scopeClass(policyItem.scope)
                            )}
                          >
                            {policyItem.scope}
                          </span>
                        </div>
                        <p className="text-[11px] text-muted-foreground mt-1 truncate">
                          {policyItem.description}
                        </p>
                        <div className="mt-1.5 flex items-center justify-between text-[10px] text-muted-foreground">
                          <span>Priority {policyItem.priority}</span>
                          <span>{policyItem.enabled ? "Enabled" : "Draft"}</span>
                        </div>
                      </button>
                    );
                  })
                )}
              </div>

              <div className="rounded-md border border-border p-2.5 bg-muted/20 text-[11px] space-y-1.5">
                <p className="font-medium">Compliance Snapshot</p>
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Identity failures</span>
                  <span className={cn(identityFailureRate > 0 ? "text-warning" : "text-success")}>
                    {identityFailureRate.toFixed(1)}%
                  </span>
                </div>
                <Progress
                  value={Math.min(100, allowRate)}
                  className="h-1.5"
                  indicatorClassName={cn(
                    allowRate >= 90 ? "bg-success" : allowRate >= 70 ? "bg-warning" : "bg-destructive"
                  )}
                />
                <p className="text-muted-foreground">
                  Recent denials: {formatNumber(policy?.recent_denials?.length ?? 0)}
                </p>
              </div>
            </CardContent>
          </Card>

          <Card className="xl:col-span-8">
            <CardHeader>
              <CardTitle className="text-sm font-semibold tracking-[0.02em] flex items-center justify-between gap-3">
                <span className="inline-flex items-center gap-2">
                  <Sliders className="h-3.5 w-3.5 text-accent" weight="duotone" />
                  Policy Creation Wizard
                </span>
                <span className="text-[10px] text-muted-foreground">
                  Step {wizardStepIndex + 1} of {WIZARD_STEPS.length}: {step.label}
                </span>
              </CardTitle>
            </CardHeader>

            <CardContent className="space-y-3.5">
              <div className="space-y-2">
                <div className="flex flex-wrap items-center gap-1.5">
                  {WIZARD_STEPS.map((wizardStep, index) => (
                    <div
                      key={wizardStep.id}
                      className={cn(
                        "rounded-md border px-2 py-1 text-[10px]",
                        index <= wizardStepIndex
                          ? "border-accent/30 bg-accent/10 text-accent"
                          : "border-border text-muted-foreground"
                      )}
                    >
                      {index + 1}. {wizardStep.label}
                    </div>
                  ))}
                </div>
                <Progress value={((wizardStepIndex + 1) / WIZARD_STEPS.length) * 100} className="h-1.5" />
              </div>

              <div className="rounded-md border border-border p-3 space-y-3 bg-card/40">
                {step.id === "intent" && (
                  <>
                    <p className="text-xs font-medium">Step 1: What do you want this policy to do?</p>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                      {(
                        [
                          { id: "allow", label: "Allow specific behavior" },
                          { id: "block", label: "Block unsafe behavior" },
                          { id: "limit", label: "Limit usage" },
                        ] as const
                      ).map((option) => (
                        <label
                          key={option.id}
                          className={cn(
                            "rounded-md border p-2.5 text-[12px] cursor-pointer",
                            wizard.intent === option.id
                              ? "border-accent/35 bg-accent/10 text-accent"
                              : "border-border"
                          )}
                        >
                          <input
                            type="radio"
                            name="intent"
                            className="mr-2"
                            checked={wizard.intent === option.id}
                            onChange={() => setWizard((current) => ({ ...current, intent: option.id }))}
                          />
                          {option.label}
                        </label>
                      ))}
                    </div>

                    <div className="space-y-1.5">
                      <p className="text-[11px] text-muted-foreground">Common intents</p>
                      <div className="flex flex-wrap gap-1.5">
                        {INTENT_PRESETS.map((preset) => (
                          <button
                            key={preset.id}
                            className="h-7 px-2 rounded-md border border-border text-[11px] hover:bg-muted/35"
                            onClick={() => setWizard((current) => applyIntentPreset(current, preset.id))}
                          >
                            {preset.label}
                          </button>
                        ))}
                      </div>
                    </div>

                    <Input
                      value={wizard.name}
                      onChange={(event) => setWizard((current) => ({ ...current, name: event.target.value }))}
                      placeholder="Policy name"
                      className={FIELD_CLASS}
                    />
                    <Input
                      value={wizard.description}
                      onChange={(event) =>
                        setWizard((current) => ({ ...current, description: event.target.value }))
                      }
                      placeholder="Optional description"
                      className={FIELD_CLASS}
                    />
                  </>
                )}

                {step.id === "scope" && (
                  <>
                    <p className="text-xs font-medium">Step 2: Where should this apply?</p>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-[12px]">
                      {(
                        [
                          { id: "global", label: "Global" },
                          { id: "organization", label: "Organization" },
                          { id: "agent", label: "Agent" },
                        ] as const
                      ).map((option) => (
                        <label
                          key={option.id}
                          className={cn(
                            "rounded-md border p-2.5 cursor-pointer",
                            wizard.scope === option.id
                              ? "border-accent/35 bg-accent/10 text-accent"
                              : "border-border"
                          )}
                        >
                          <input
                            type="radio"
                            name="scope"
                            className="mr-2"
                            checked={wizard.scope === option.id}
                            onChange={() => setWizard((current) => ({ ...current, scope: option.id }))}
                          />
                          {option.label}
                        </label>
                      ))}
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-[12px]">
                      <label className="inline-flex items-center gap-2 rounded-md border border-border p-2.5">
                        <input
                          type="checkbox"
                          checked={wizard.trafficApi}
                          onChange={(event) =>
                            setWizard((current) => ({ ...current, trafficApi: event.target.checked }))
                          }
                        />
                        API requests
                      </label>
                      <label className="inline-flex items-center gap-2 rounded-md border border-border p-2.5">
                        <input
                          type="checkbox"
                          checked={wizard.trafficTools}
                          onChange={(event) =>
                            setWizard((current) => ({ ...current, trafficTools: event.target.checked }))
                          }
                        />
                        Tool calls
                      </label>
                      <label className="inline-flex items-center gap-2 rounded-md border border-border p-2.5 text-muted-foreground">
                        <input
                          type="checkbox"
                          checked={wizard.trafficApi && wizard.trafficTools}
                          onChange={(event) =>
                            setWizard((current) => ({
                              ...current,
                              trafficApi: event.target.checked,
                              trafficTools: event.target.checked,
                            }))
                          }
                        />
                        All
                      </label>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-[12px]">
                      {(
                        [
                          { id: "all", label: "All traffic" },
                          { id: "endpoint", label: "Specific endpoint(s)" },
                          { id: "tool", label: "Specific tool(s)" },
                        ] as const
                      ).map((option) => (
                        <label
                          key={option.id}
                          className={cn(
                            "rounded-md border p-2.5 cursor-pointer",
                            wizard.target === option.id
                              ? "border-accent/35 bg-accent/10 text-accent"
                              : "border-border"
                          )}
                        >
                          <input
                            type="radio"
                            name="target"
                            className="mr-2"
                            checked={wizard.target === option.id}
                            onChange={() => setWizard((current) => ({ ...current, target: option.id }))}
                          />
                          {option.label}
                        </label>
                      ))}
                    </div>

                    {wizard.target === "endpoint" && (
                      <Input
                        value={wizard.endpointPattern}
                        onChange={(event) =>
                          setWizard((current) => ({ ...current, endpointPattern: event.target.value }))
                        }
                        placeholder="Endpoint pattern, e.g. /backend-api/*"
                        className={FIELD_CLASS}
                      />
                    )}

                    {wizard.target === "tool" && (
                      <Input
                        value={wizard.toolName}
                        onChange={(event) =>
                          setWizard((current) => ({ ...current, toolName: event.target.value }))
                        }
                        placeholder="Tool name, e.g. tools/call/echo"
                        className={FIELD_CLASS}
                      />
                    )}
                  </>
                )}

                {step.id === "conditions" && (
                  <>
                    <p className="text-xs font-medium">Step 3: When should this policy trigger?</p>

                    <div className="space-y-2 rounded-md border border-border p-2.5">
                      <p className="text-[11px] text-muted-foreground">Model</p>
                      <label className="inline-flex items-center gap-2 text-[12px]">
                        <input
                          type="checkbox"
                          checked={wizard.anyModel}
                          onChange={(event) =>
                            setWizard((current) => ({ ...current, anyModel: event.target.checked }))
                          }
                        />
                        Any model
                      </label>
                      {!wizard.anyModel && (
                        <Input
                          value={wizard.model}
                          onChange={(event) =>
                            setWizard((current) => ({ ...current, model: event.target.value }))
                          }
                          placeholder="Model id, e.g. gpt-5.2-pro"
                          className={FIELD_CLASS}
                        />
                      )}
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      <label className="rounded-md border border-border p-2.5 text-[12px] space-y-1">
                        <div className="inline-flex items-center gap-2">
                          <input
                            type="checkbox"
                            checked={wizard.costEnabled}
                            onChange={(event) =>
                              setWizard((current) => ({ ...current, costEnabled: event.target.checked }))
                            }
                          />
                          Cost per request exceeds
                        </div>
                        {wizard.costEnabled && (
                          <Input
                            type="number"
                            min="0"
                            step="0.001"
                            value={wizard.costThreshold}
                            onChange={(event) =>
                              setWizard((current) => ({
                                ...current,
                                costThreshold: Number(event.target.value) || 0,
                              }))
                            }
                            className={FIELD_CLASS}
                          />
                        )}
                      </label>

                      <label className="rounded-md border border-border p-2.5 text-[12px] space-y-1">
                        <div className="inline-flex items-center gap-2">
                          <input
                            type="checkbox"
                            checked={wizard.rateEnabled}
                            onChange={(event) =>
                              setWizard((current) => ({ ...current, rateEnabled: event.target.checked }))
                            }
                          />
                          Rate exceeds requests/min
                        </div>
                        {wizard.rateEnabled && (
                          <Input
                            type="number"
                            min="1"
                            value={wizard.rateThreshold}
                            onChange={(event) =>
                              setWizard((current) => ({
                                ...current,
                                rateThreshold: Number(event.target.value) || 0,
                              }))
                            }
                            className={FIELD_CLASS}
                          />
                        )}
                      </label>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[12px]">
                      <label className="inline-flex items-center gap-2 rounded-md border border-border p-2.5">
                        <input
                          type="checkbox"
                          checked={wizard.piiEnabled}
                          onChange={(event) =>
                            setWizard((current) => ({ ...current, piiEnabled: event.target.checked }))
                          }
                        />
                        PII detected
                      </label>
                      <label className="inline-flex items-center gap-2 rounded-md border border-border p-2.5">
                        <input
                          type="checkbox"
                          checked={wizard.metadataEnabled}
                          onChange={(event) =>
                            setWizard((current) => ({ ...current, metadataEnabled: event.target.checked }))
                          }
                        />
                        Match request metadata
                      </label>
                    </div>

                    {wizard.metadataEnabled && (
                      <Input
                        value={wizard.metadataQuery}
                        onChange={(event) =>
                          setWizard((current) => ({ ...current, metadataQuery: event.target.value }))
                        }
                        placeholder="Metadata contains..."
                        className={FIELD_CLASS}
                      />
                    )}

                    <p className="text-[11px] text-muted-foreground">Conditions are ANDed by default.</p>
                  </>
                )}

                {step.id === "action" && (
                  <>
                    <p className="text-xs font-medium">Step 4: What action should happen?</p>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[12px]">
                      {(
                        [
                          { id: "allow", label: "Allow (override)" },
                          { id: "deny", label: "Deny request" },
                          { id: "rate_limit", label: "Rate-limit" },
                          { id: "log", label: "Log only (no enforcement)" },
                        ] as const
                      ).map((option) => (
                        <label
                          key={option.id}
                          className={cn(
                            "rounded-md border p-2.5 cursor-pointer",
                            wizard.action === option.id
                              ? "border-accent/35 bg-accent/10 text-accent"
                              : "border-border"
                          )}
                        >
                          <input
                            type="radio"
                            className="mr-2"
                            checked={wizard.action === option.id}
                            onChange={() => setWizard((current) => ({ ...current, action: option.id }))}
                          />
                          {option.label}
                        </label>
                      ))}
                    </div>

                    <Input
                      value={wizard.reason}
                      onChange={(event) => setWizard((current) => ({ ...current, reason: event.target.value }))}
                      placeholder="Reason shown to caller"
                      className={FIELD_CLASS}
                    />

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[12px]">
                      <label className="inline-flex items-center gap-2 rounded-md border border-border p-2.5">
                        <input
                          type="checkbox"
                          checked={wizard.emitAlert}
                          onChange={(event) =>
                            setWizard((current) => ({ ...current, emitAlert: event.target.checked }))
                          }
                        />
                        Emit alert
                      </label>
                      <label className="inline-flex items-center gap-2 rounded-md border border-border p-2.5">
                        <input
                          type="checkbox"
                          checked={wizard.recordCostAvoided}
                          onChange={(event) =>
                            setWizard((current) => ({ ...current, recordCostAvoided: event.target.checked }))
                          }
                        />
                        Record cost avoided
                      </label>
                    </div>
                  </>
                )}

                {step.id === "impact" && (
                  <>
                    <p className="text-xs font-medium">Step 5: Impact preview (required)</p>

                    <div className="rounded-md border border-border p-2.5 space-y-1.5 text-[12px]">
                      {budgetPrimitives.isLoading ? (
                        <p className="text-muted-foreground">Loading recent traffic primitives...</p>
                      ) : (
                        <>
                          <p>
                            • Affect ~{formatNumber(impactPreview.affectedCount)} requests ({impactPreview.affectedPct.toFixed(2)}% of sampled traffic)
                          </p>
                          <p>
                            • Block high-cost calls: {formatNumber(impactPreview.highCostBlockedCalls)}
                          </p>
                          <p>
                            • Estimated monthly impact: {toFixedMoney(impactPreview.estimatedMonthlySavingsUsd)}
                          </p>
                          <p>
                            • Latency regression: {wizard.action === "deny" || wizard.action === "log" ? "Not expected" : "Possible under limit pressure"}
                          </p>
                        </>
                      )}
                    </div>

                    {impactPreview.sampleRequests.length > 0 && (
                      <div className="rounded-md border border-border p-2.5 space-y-1.5">
                        <p className="text-[11px] text-muted-foreground">Sample affected requests</p>
                        {impactPreview.sampleRequests.map((request, index) => (
                          <div key={`${request.request_id ?? "no-id"}-${index}`} className="text-[11px] font-mono">
                            {request.method} {request.path} {request.model ? `(${request.model})` : ""} {toFixedMoney(request.cost_usd ?? 0)}
                          </div>
                        ))}
                      </div>
                    )}

                    {impactPreview.notes.length > 0 && (
                      <div className="rounded-md border border-warning/30 bg-warning/10 p-2 space-y-1 text-[11px] text-warning">
                        {impactPreview.notes.map((note) => (
                          <div key={note}>• {note}</div>
                        ))}
                      </div>
                    )}

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[12px]">
                      <label
                        className={cn(
                          "rounded-md border p-2.5 cursor-pointer",
                          wizard.executionMode === "enforce"
                            ? "border-accent/35 bg-accent/10 text-accent"
                            : "border-border"
                        )}
                      >
                        <input
                          type="radio"
                          className="mr-2"
                          checked={wizard.executionMode === "enforce"}
                          onChange={() =>
                            setWizard((current) => ({
                              ...current,
                              executionMode: "enforce",
                            }))
                          }
                        />
                        Enforce immediately
                      </label>
                      <label
                        className={cn(
                          "rounded-md border p-2.5 cursor-pointer",
                          wizard.executionMode === "dry_run"
                            ? "border-accent/35 bg-accent/10 text-accent"
                            : "border-border"
                        )}
                      >
                        <input
                          type="radio"
                          className="mr-2"
                          checked={wizard.executionMode === "dry_run"}
                          onChange={() =>
                            setWizard((current) => ({
                              ...current,
                              executionMode: "dry_run",
                            }))
                          }
                        />
                        Dry-run (observe only)
                      </label>
                    </div>
                  </>
                )}

                {step.id === "review" && (
                  <>
                    <p className="text-xs font-medium">Step 6: Review and create</p>

                    <div className="rounded-md border border-border p-2.5 space-y-1.5 text-[12px]">
                      <p className="font-medium">{wizard.name || "Unnamed policy"}</p>
                      <p className="text-muted-foreground">Scope: {wizard.scope}</p>
                      <p className="text-muted-foreground">
                        Target: {wizard.target === "endpoint" ? wizard.endpointPattern : wizard.target === "tool" ? wizard.toolName : "All traffic"}
                      </p>
                      <p className="text-muted-foreground">
                        Conditions: {wizard.anyModel ? "any model" : `model=${wizard.model}`}
                        {wizard.costEnabled ? `, cost>${wizard.costThreshold}` : ""}
                        {wizard.rateEnabled ? `, rate>${wizard.rateThreshold}/min` : ""}
                        {wizard.piiEnabled ? ", pii_detected" : ""}
                        {wizard.metadataEnabled && wizard.metadataQuery ? `, metadata~${wizard.metadataQuery}` : ""}
                      </p>
                      <p className="text-muted-foreground">Action: {wizard.action}</p>
                      <p className="text-muted-foreground">
                        Impact estimate: {formatNumber(impactPreview.affectedCount)} req/day, {toFixedMoney(impactPreview.estimatedMonthlySavingsUsd)}/month
                      </p>
                    </div>

                    {wizard.target === "all" && (
                      <label className="inline-flex items-center gap-2 rounded-md border border-warning/30 bg-warning/10 p-2.5 text-[12px] text-warning">
                        <input
                          type="checkbox"
                          checked={confirmAllTraffic}
                          onChange={(event) => setConfirmAllTraffic(event.target.checked)}
                        />
                        Confirm this applies to all traffic.
                      </label>
                    )}

                    {runtimeGapWarnings.length > 0 && (
                      <div className="rounded-md border border-warning/30 bg-warning/10 p-2 text-[11px] text-warning space-y-1">
                        <div className="font-medium">Runtime compatibility notes</div>
                        {runtimeGapWarnings.map((warningText) => (
                          <div key={warningText}>• {warningText}</div>
                        ))}
                      </div>
                    )}

                    {lastCreatedPolicyId && selectedPolicy?.id === lastCreatedPolicyId && (
                      <div className="rounded-md border border-success/30 bg-success/10 p-2.5 text-[11px] text-success">
                        Policy created. Next: validate in Observability and monitor Policy Activity for first trigger.
                      </div>
                    )}

                    <div className="flex items-center gap-2">
                      <Button
                        size="sm"
                        className="h-8 px-3 text-[11px]"
                        onClick={() => createPolicy(false)}
                        disabled={!isStepValid("review")}
                      >
                        Create Policy
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-8 px-3 text-[11px]"
                        onClick={() => createPolicy(true)}
                      >
                        Save as Draft
                      </Button>
                    </div>
                  </>
                )}
              </div>

              <div className="flex items-center justify-between gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  className="h-8 px-2.5 text-[11px]"
                  onClick={goBack}
                  disabled={wizardStepIndex === 0}
                >
                  Back
                </Button>
                <div className="flex items-center gap-2">
                  <Button
                    size="sm"
                    variant="outline"
                    className="h-8 px-2.5 text-[11px]"
                    onClick={resetWizard}
                  >
                    Reset
                  </Button>
                  <Button
                    size="sm"
                    className="h-8 px-2.5 text-[11px]"
                    onClick={goNext}
                    disabled={wizardStepIndex === WIZARD_STEPS.length - 1 || !isStepValid(step.id)}
                  >
                    Next
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-semibold tracking-[0.02em] flex items-center justify-between gap-2">
              <span className="inline-flex items-center gap-2">
                <FileCode className="h-3.5 w-3.5 text-accent" weight="duotone" />
                Selected Policy Artifacts
              </span>
              <span className="text-[10px] text-muted-foreground">Generated after wizard creation</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2.5">
            {!selectedPolicy ? (
              <div className="text-[12px] text-muted-foreground">Select or create a policy to inspect artifacts.</div>
            ) : (
              <>
                <div className="flex items-center gap-1.5">
                  {(
                    [
                      { id: "summary", label: "Summary" },
                      { id: "policy-data", label: "Policy Data" },
                      { id: "rego", label: "Rego" },
                    ] as const
                  ).map((view) => (
                    <button
                      key={view.id}
                      className={cn(
                        "h-7 px-2.5 rounded-md border text-[11px]",
                        artifactView === view.id
                          ? "border-accent/35 bg-accent/10 text-accent"
                          : "border-border text-muted-foreground"
                      )}
                      onClick={() => setArtifactView(view.id)}
                    >
                      {view.label}
                    </button>
                  ))}
                </div>

                {artifactView === "summary" && (
                  <div className="rounded-md border border-border p-2.5 space-y-2">
                    <div className="text-[12px] font-medium">{selectedPolicy.name}</div>
                    <div className="text-[11px] text-muted-foreground">{selectedPolicy.description}</div>
                    <pre className="text-[11px] text-muted-foreground whitespace-pre-wrap leading-5">
                      {applyGuide}
                    </pre>
                  </div>
                )}

                {artifactView === "policy-data" && (
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <p className="text-[11px] text-muted-foreground">Runtime-enforced policy_data JSON</p>
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-7 px-2.5 text-[11px]"
                        onClick={() => copyText("policy-data", policyDataJson)}
                      >
                        <Copy className="h-3.5 w-3.5 mr-1" />
                        {copiedKey === "policy-data" ? "Copied" : "Copy JSON"}
                      </Button>
                    </div>
                    <textarea
                      readOnly
                      value={policyDataJson}
                      className={CODE_AREA_CLASS}
                    />
                  </div>
                )}

                {artifactView === "rego" && (
                  <div className="space-y-2">
                    <div className="rounded-md border border-warning/30 bg-warning/10 p-2 text-[11px] text-warning flex items-start gap-2">
                      <Warning className="h-3.5 w-3.5 mt-0.5" />
                      Current runtime does not execute loaded Rego modules; enforce mode uses policy_data.
                    </div>
                    <div className="flex items-center justify-between">
                      <p className="text-[11px] text-muted-foreground">Generated scaffold for parity and future runtime upgrades.</p>
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-7 px-2.5 text-[11px]"
                        onClick={() => copyText("rego", regoScaffold)}
                      >
                        <FileCode className="h-3.5 w-3.5 mr-1" />
                        {copiedKey === "rego" ? "Copied" : "Copy Rego"}
                      </Button>
                    </div>
                    <textarea
                      readOnly
                      value={regoScaffold}
                      className={CODE_AREA_CLASS}
                    />
                  </div>
                )}
              </>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-semibold tracking-[0.02em]">
              <XCircle className="h-3.5 w-3.5 text-warning" weight="duotone" />
              Recent Denials
            </CardTitle>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <div className="space-y-2">
                {Array.from({ length: 4 }).map((_, index) => (
                  <Skeleton key={index} className="h-14 w-full" />
                ))}
              </div>
            ) : (policy?.recent_denials?.length ?? 0) === 0 ? (
              <div className="text-[12px] text-muted-foreground">No recent denials recorded.</div>
            ) : (
              <div className="space-y-2">
                {policy?.recent_denials.map((denial, index) => (
                  <div
                    key={`${denial.timestamp}-${index}`}
                    className="rounded-md border border-destructive/25 bg-destructive/8 p-2.5"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="text-[12px] font-medium truncate">{denial.method}</div>
                      <div className="text-[10px] text-muted-foreground">{formatTimestamp(denial.timestamp)}</div>
                    </div>
                    <div className="text-[11px] text-muted-foreground mt-1">{denial.reason}</div>
                    {denial.tool && (
                      <div className="mt-1 text-[10px] text-muted-foreground font-mono">{denial.tool}</div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
