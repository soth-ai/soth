use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use soth_core::artifacts::ArtifactKind;
use soth_core::normalized::EndpointType;
use soth_core::policy::{
    DeploymentModel, MatchedRule, PolicyContext, PolicyDecision, PolicyDecisionKind, PolicyWarning,
    RedactTarget, RerouteTarget, RuleKind,
};
use soth_core::{
    AnomalyFlag, AppType, NormalizedRequest, SensitiveArtifact, TrafficClassification,
    UseCaseLabel, VolatilityClass,
};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct PolicyBundle {
    pub metadata: PolicyBundleMetadata,
    pub system_rules: Arc<CompiledRuleSet>,
    pub org_rules: Arc<CompiledRuleSet>,
    pub org_patterns: Arc<OrgPatterns>,
    pub budget_limits: BudgetLimits,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyBundleMetadata {
    pub bundle_version: String,
    pub schema_version: String,
    pub org_id: String,
    pub signed_at: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BudgetLimits {
    pub max_tokens_per_session: Option<u64>,
    pub max_cost_usd_per_session: Option<f64>,
    pub max_requests_per_session: Option<u32>,
    pub max_tokens_per_day: Option<u64>,
    pub max_cost_usd_per_day: Option<f64>,
}

impl Default for BudgetLimits {
    fn default() -> Self {
        Self {
            max_tokens_per_session: None,
            max_cost_usd_per_session: None,
            max_requests_per_session: None,
            max_tokens_per_day: None,
            max_cost_usd_per_day: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct OrgPatterns {
    #[serde(default)]
    pub patterns: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct CompiledRuleSet {
    pub rules: Vec<CompiledRule>,
}

impl Default for CompiledRuleSet {
    fn default() -> Self {
        Self { rules: Vec::new() }
    }
}

#[derive(Clone, Debug)]
pub struct CompiledRule {
    pub rule_id: String,
    pub rule_name: String,
    pub rule_kind: RuleKind,
    pub cel_expr: String,
    compiled_expr: CelExpr,
    pub action: RuleAction,
}

#[derive(Clone, Debug)]
enum CelExpr {
    Bool(bool),
    Number(f64),
    String(String),
    Null,
    Field(String),
    Array(Vec<CelExpr>),
    Not(Box<CelExpr>),
    And(Box<CelExpr>, Box<CelExpr>),
    Or(Box<CelExpr>, Box<CelExpr>),
    Eq(Box<CelExpr>, Box<CelExpr>),
    Ne(Box<CelExpr>, Box<CelExpr>),
    Gt(Box<CelExpr>, Box<CelExpr>),
    Gte(Box<CelExpr>, Box<CelExpr>),
    Lt(Box<CelExpr>, Box<CelExpr>),
    Lte(Box<CelExpr>, Box<CelExpr>),
    Contains(Box<CelExpr>, Box<CelExpr>),
}

#[derive(Clone, Debug, PartialEq)]
enum EvalValue {
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<EvalValue>),
    Null,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RuleDefinition {
    pub rule_id: String,
    pub rule_name: String,
    pub cel_expr: String,
    pub action: RuleAction,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RuleAction {
    Block { status: u16, message: String },
    Redact { targets: Vec<RedactTarget> },
    Reroute { target: RerouteTarget },
    Flag { reason: String },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignedPolicyBundle {
    pub payload: PolicyBundlePayload,
    pub signature: String,
    pub public_key: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PolicyBundlePayload {
    pub metadata: PolicyBundleMetadata,
    #[serde(default)]
    pub system_rules: Vec<RuleDefinition>,
    #[serde(default)]
    pub org_rules: Vec<RuleDefinition>,
    #[serde(default)]
    pub org_patterns: OrgPatterns,
    #[serde(default)]
    pub budget_limits: BudgetLimits,
}

#[derive(Debug, Error)]
pub enum PolicyBundleError {
    #[error("failed to read bundle: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid bundle json: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
    #[error("invalid rule {rule_id}: {error}")]
    InvalidRule { rule_id: String, error: String },
}

pub fn evaluate(
    normalized: &NormalizedRequest,
    artifacts: &[SensitiveArtifact],
    ctx: &PolicyContext,
    bundle: &PolicyBundle,
) -> PolicyDecision {
    let started = Instant::now();

    if let Some(block) = evaluate_budget_limits(ctx, bundle) {
        return with_latency(block, started);
    }

    if let Some(block) = evaluate_system_rules(normalized, artifacts) {
        return with_latency(block, started);
    }

    if ctx.skip_org_rules {
        return with_latency(allow_decision(), started);
    }

    let (decision, warnings) = evaluate_org_rules(normalized, artifacts, ctx, bundle);
    if let Some(mut decision) = decision {
        decision.warnings = warnings;
        return with_latency(decision, started);
    }

    let mut allow = allow_decision();
    allow.warnings = warnings;
    with_latency(allow, started)
}

pub fn warm(bundle: &PolicyBundle) {
    let _ = bundle.system_rules.rules.len();
    let _ = bundle.org_rules.rules.len();
}

pub fn load_bundle(path: &Path) -> Result<PolicyBundle, PolicyBundleError> {
    let bytes = std::fs::read(path)?;
    load_bundle_from_bytes(&bytes)
}

pub fn load_bundle_from_bytes(bytes: &[u8]) -> Result<PolicyBundle, PolicyBundleError> {
    let envelope: SignedPolicyBundle = serde_json::from_slice(bytes)?;
    verify_bundle_signature(&envelope.payload, &envelope.signature, &envelope.public_key)?;

    let system_rules = compile_rule_set(&envelope.payload.system_rules, RuleKind::System)?;
    let org_rules = compile_rule_set(&envelope.payload.org_rules, RuleKind::Org)?;

    Ok(PolicyBundle {
        metadata: envelope.payload.metadata,
        system_rules: Arc::new(system_rules),
        org_rules: Arc::new(org_rules),
        org_patterns: Arc::new(envelope.payload.org_patterns),
        budget_limits: envelope.payload.budget_limits,
    })
}

fn verify_bundle_signature(
    payload: &PolicyBundlePayload,
    signature_b64: &str,
    public_key_b64: &str,
) -> Result<(), PolicyBundleError> {
    let payload_bytes = serde_json::to_vec(payload)?;

    let signature_bytes = B64
        .decode(signature_b64)
        .map_err(|error| PolicyBundleError::InvalidSignature(error.to_string()))?;
    let public_key_bytes = B64
        .decode(public_key_b64)
        .map_err(|error| PolicyBundleError::InvalidSignature(error.to_string()))?;

    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|error| PolicyBundleError::InvalidSignature(error.to_string()))?;
    let key_bytes: [u8; 32] = public_key_bytes.as_slice().try_into().map_err(|_| {
        PolicyBundleError::InvalidSignature("public key must be 32 bytes".to_string())
    })?;
    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|error| PolicyBundleError::InvalidSignature(error.to_string()))?;

    verifying_key
        .verify(&payload_bytes, &signature)
        .map_err(|error| PolicyBundleError::InvalidSignature(error.to_string()))
}

fn compile_rule_set(
    source_rules: &[RuleDefinition],
    kind: RuleKind,
) -> Result<CompiledRuleSet, PolicyBundleError> {
    let mut rules = Vec::with_capacity(source_rules.len());
    for rule in source_rules {
        if rule.rule_id.trim().is_empty() {
            return Err(PolicyBundleError::InvalidRule {
                rule_id: "<missing>".to_string(),
                error: "rule_id must not be empty".to_string(),
            });
        }
        if rule.rule_name.trim().is_empty() {
            return Err(PolicyBundleError::InvalidRule {
                rule_id: rule.rule_id.clone(),
                error: "rule_name must not be empty".to_string(),
            });
        }
        let compiled_expr = compile_cel_expression(&rule.rule_id, &rule.cel_expr)?;
        rules.push(CompiledRule {
            rule_id: rule.rule_id.clone(),
            rule_name: rule.rule_name.clone(),
            rule_kind: kind.clone(),
            cel_expr: rule.cel_expr.clone(),
            compiled_expr,
            action: rule.action.clone(),
        });
    }
    Ok(CompiledRuleSet { rules })
}

fn compile_cel_expression(rule_id: &str, expr: &str) -> Result<CelExpr, PolicyBundleError> {
    let tokens = tokenize_expression(expr).map_err(|error| PolicyBundleError::InvalidRule {
        rule_id: rule_id.to_string(),
        error,
    })?;

    let mut parser = ExprParser::new(tokens);
    let compiled = parser
        .parse_expression()
        .map_err(|error| PolicyBundleError::InvalidRule {
            rule_id: rule_id.to_string(),
            error,
        })?;
    parser
        .expect_end()
        .map_err(|error| PolicyBundleError::InvalidRule {
            rule_id: rule_id.to_string(),
            error,
        })?;
    Ok(compiled)
}

#[derive(Clone, Debug, PartialEq)]
enum Token {
    Ident(String),
    Number(f64),
    String(String),
    True,
    False,
    Null,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
    Dot,
    And,
    Or,
    Not,
    Eq,
    Ne,
    Gt,
    Gte,
    Lt,
    Lte,
}

struct ExprParser {
    tokens: Vec<Token>,
    pos: usize,
}

impl ExprParser {
    fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn parse_expression(&mut self) -> Result<CelExpr, String> {
        self.parse_or()
    }

    fn expect_end(&self) -> Result<(), String> {
        if self.pos == self.tokens.len() {
            Ok(())
        } else {
            Err("unexpected trailing tokens".to_string())
        }
    }

    fn parse_or(&mut self) -> Result<CelExpr, String> {
        let mut expr = self.parse_and()?;
        loop {
            if self.consume_token(Token::Or) {
                let rhs = self.parse_and()?;
                expr = CelExpr::Or(Box::new(expr), Box::new(rhs));
                continue;
            }
            break;
        }
        Ok(expr)
    }

    fn parse_and(&mut self) -> Result<CelExpr, String> {
        let mut expr = self.parse_unary()?;
        loop {
            if self.consume_token(Token::And) {
                let rhs = self.parse_unary()?;
                expr = CelExpr::And(Box::new(expr), Box::new(rhs));
                continue;
            }
            break;
        }
        Ok(expr)
    }

    fn parse_unary(&mut self) -> Result<CelExpr, String> {
        if self.consume_token(Token::Not) {
            let rhs = self.parse_unary()?;
            return Ok(CelExpr::Not(Box::new(rhs)));
        }
        self.parse_comparison()
    }

    fn parse_comparison(&mut self) -> Result<CelExpr, String> {
        let lhs = self.parse_primary()?;
        if self.consume_token(Token::Eq) {
            let rhs = self.parse_primary()?;
            return Ok(CelExpr::Eq(Box::new(lhs), Box::new(rhs)));
        }
        if self.consume_token(Token::Ne) {
            let rhs = self.parse_primary()?;
            return Ok(CelExpr::Ne(Box::new(lhs), Box::new(rhs)));
        }
        if self.consume_token(Token::Gte) {
            let rhs = self.parse_primary()?;
            return Ok(CelExpr::Gte(Box::new(lhs), Box::new(rhs)));
        }
        if self.consume_token(Token::Lte) {
            let rhs = self.parse_primary()?;
            return Ok(CelExpr::Lte(Box::new(lhs), Box::new(rhs)));
        }
        if self.consume_token(Token::Gt) {
            let rhs = self.parse_primary()?;
            return Ok(CelExpr::Gt(Box::new(lhs), Box::new(rhs)));
        }
        if self.consume_token(Token::Lt) {
            let rhs = self.parse_primary()?;
            return Ok(CelExpr::Lt(Box::new(lhs), Box::new(rhs)));
        }
        Ok(lhs)
    }

    fn parse_primary(&mut self) -> Result<CelExpr, String> {
        let expr = match self.next_token() {
            Some(Token::True) => CelExpr::Bool(true),
            Some(Token::False) => CelExpr::Bool(false),
            Some(Token::Null) => CelExpr::Null,
            Some(Token::Number(value)) => CelExpr::Number(value),
            Some(Token::String(value)) => CelExpr::String(value),
            Some(Token::LParen) => {
                let expr = self.parse_expression()?;
                self.expect_token(Token::RParen)?;
                expr
            }
            Some(Token::LBracket) => self.parse_array_literal()?,
            Some(Token::Ident(first)) => self.parse_field_reference(first)?,
            Some(token) => {
                return Err(format!(
                    "unexpected token in primary expression: {}",
                    token_label(&token)
                ));
            }
            None => return Err("unexpected end of expression".to_string()),
        };

        self.parse_postfix(expr)
    }

    fn parse_array_literal(&mut self) -> Result<CelExpr, String> {
        let mut values = Vec::new();
        if self.consume_token(Token::RBracket) {
            return Ok(CelExpr::Array(values));
        }

        loop {
            values.push(self.parse_expression()?);
            if self.consume_token(Token::Comma) {
                continue;
            }
            self.expect_token(Token::RBracket)?;
            break;
        }
        Ok(CelExpr::Array(values))
    }

    fn parse_field_reference(&mut self, first: String) -> Result<CelExpr, String> {
        let mut path = vec![first];
        loop {
            if self.looks_like_contains_call() {
                break;
            }

            if !self.consume_token(Token::Dot) {
                break;
            }

            let segment = self.expect_ident()?;
            path.push(segment);
        }

        Ok(CelExpr::Field(path.join(".")))
    }

    fn parse_postfix(&mut self, mut expr: CelExpr) -> Result<CelExpr, String> {
        loop {
            if !self.looks_like_contains_call() {
                break;
            }
            self.expect_token(Token::Dot)?;
            let method = self.expect_ident()?;
            if method != "contains" {
                return Err(format!("unsupported method call: {method}"));
            }
            self.expect_token(Token::LParen)?;
            let argument = self.parse_expression()?;
            self.expect_token(Token::RParen)?;
            expr = CelExpr::Contains(Box::new(expr), Box::new(argument));
        }
        Ok(expr)
    }

    fn looks_like_contains_call(&self) -> bool {
        matches!(self.peek_token(), Some(Token::Dot))
            && matches!(self.peek_n(1), Some(Token::Ident(name)) if name == "contains")
            && matches!(self.peek_n(2), Some(Token::LParen))
    }

    fn expect_ident(&mut self) -> Result<String, String> {
        match self.next_token() {
            Some(Token::Ident(value)) => Ok(value),
            Some(token) => Err(format!(
                "expected identifier but found {}",
                token_label(&token)
            )),
            None => Err("expected identifier but reached end of expression".to_string()),
        }
    }

    fn consume_token(&mut self, expected: Token) -> bool {
        if let Some(actual) = self.peek_token() {
            if *actual == expected {
                self.pos += 1;
                return true;
            }
        }
        false
    }

    fn expect_token(&mut self, expected: Token) -> Result<(), String> {
        if self.consume_token(expected.clone()) {
            Ok(())
        } else {
            let found = self
                .peek_token()
                .map(token_label)
                .unwrap_or_else(|| "end_of_input".to_string());
            Err(format!(
                "expected token {} but found {found}",
                token_label(&expected)
            ))
        }
    }

    fn peek_token(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn peek_n(&self, offset: usize) -> Option<&Token> {
        self.tokens.get(self.pos + offset)
    }

    fn next_token(&mut self) -> Option<Token> {
        if self.pos >= self.tokens.len() {
            return None;
        }
        let out = self.tokens[self.pos].clone();
        self.pos += 1;
        Some(out)
    }
}

fn token_label(token: &Token) -> String {
    match token {
        Token::Ident(value) => format!("ident({value})"),
        Token::Number(value) => format!("number({value})"),
        Token::String(_) => "string".to_string(),
        Token::True => "true".to_string(),
        Token::False => "false".to_string(),
        Token::Null => "null".to_string(),
        Token::LParen => "(".to_string(),
        Token::RParen => ")".to_string(),
        Token::LBracket => "[".to_string(),
        Token::RBracket => "]".to_string(),
        Token::Comma => ",".to_string(),
        Token::Dot => ".".to_string(),
        Token::And => "&&".to_string(),
        Token::Or => "||".to_string(),
        Token::Not => "!".to_string(),
        Token::Eq => "==".to_string(),
        Token::Ne => "!=".to_string(),
        Token::Gt => ">".to_string(),
        Token::Gte => ">=".to_string(),
        Token::Lt => "<".to_string(),
        Token::Lte => "<=".to_string(),
    }
}

fn tokenize_expression(input: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let chars = input.chars().collect::<Vec<_>>();
    let mut idx = 0usize;

    while idx < chars.len() {
        let ch = chars[idx];
        if ch.is_ascii_whitespace() {
            idx += 1;
            continue;
        }

        match ch {
            '(' => {
                tokens.push(Token::LParen);
                idx += 1;
            }
            ')' => {
                tokens.push(Token::RParen);
                idx += 1;
            }
            '[' => {
                tokens.push(Token::LBracket);
                idx += 1;
            }
            ']' => {
                tokens.push(Token::RBracket);
                idx += 1;
            }
            ',' => {
                tokens.push(Token::Comma);
                idx += 1;
            }
            '.' => {
                tokens.push(Token::Dot);
                idx += 1;
            }
            '&' => {
                if idx + 1 < chars.len() && chars[idx + 1] == '&' {
                    tokens.push(Token::And);
                    idx += 2;
                } else {
                    return Err("single '&' is not allowed; use '&&'".to_string());
                }
            }
            '|' => {
                if idx + 1 < chars.len() && chars[idx + 1] == '|' {
                    tokens.push(Token::Or);
                    idx += 2;
                } else {
                    return Err("single '|' is not allowed; use '||'".to_string());
                }
            }
            '=' => {
                if idx + 1 < chars.len() && chars[idx + 1] == '=' {
                    tokens.push(Token::Eq);
                    idx += 2;
                } else {
                    return Err("single '=' is not allowed; use '=='".to_string());
                }
            }
            '!' => {
                if idx + 1 < chars.len() && chars[idx + 1] == '=' {
                    tokens.push(Token::Ne);
                    idx += 2;
                } else {
                    tokens.push(Token::Not);
                    idx += 1;
                }
            }
            '>' => {
                if idx + 1 < chars.len() && chars[idx + 1] == '=' {
                    tokens.push(Token::Gte);
                    idx += 2;
                } else {
                    tokens.push(Token::Gt);
                    idx += 1;
                }
            }
            '<' => {
                if idx + 1 < chars.len() && chars[idx + 1] == '=' {
                    tokens.push(Token::Lte);
                    idx += 2;
                } else {
                    tokens.push(Token::Lt);
                    idx += 1;
                }
            }
            '"' => {
                let (value, consumed) = parse_string_literal(&chars[idx..])?;
                tokens.push(Token::String(value));
                idx += consumed;
            }
            value if value.is_ascii_digit() => {
                let (number, consumed) = parse_number_literal(&chars[idx..])?;
                tokens.push(Token::Number(number));
                idx += consumed;
            }
            value if is_ident_start(value) => {
                let (ident, consumed) = parse_identifier(&chars[idx..]);
                match ident.as_str() {
                    "true" => tokens.push(Token::True),
                    "false" => tokens.push(Token::False),
                    "null" => tokens.push(Token::Null),
                    _ => tokens.push(Token::Ident(ident)),
                }
                idx += consumed;
            }
            _ => return Err(format!("unsupported token '{ch}' in expression")),
        }
    }

    Ok(tokens)
}

fn parse_string_literal(chars: &[char]) -> Result<(String, usize), String> {
    if chars.is_empty() || chars[0] != '"' {
        return Err("string literal must start with quote".to_string());
    }
    let mut out = String::new();
    let mut idx = 1usize;
    let mut escaped = false;

    while idx < chars.len() {
        let ch = chars[idx];
        idx += 1;

        if escaped {
            let decoded = match ch {
                '"' => '"',
                '\\' => '\\',
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                other => other,
            };
            out.push(decoded);
            escaped = false;
            continue;
        }

        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            return Ok((out, idx));
        }
        out.push(ch);
    }

    Err("unterminated string literal".to_string())
}

fn parse_number_literal(chars: &[char]) -> Result<(f64, usize), String> {
    let mut idx = 0usize;
    let mut has_dot = false;
    while idx < chars.len() {
        let ch = chars[idx];
        if ch.is_ascii_digit() {
            idx += 1;
            continue;
        }
        if ch == '.' && !has_dot {
            has_dot = true;
            idx += 1;
            continue;
        }
        break;
    }

    let text = chars[..idx].iter().collect::<String>();
    let value = text
        .parse::<f64>()
        .map_err(|error| format!("invalid numeric literal '{text}': {error}"))?;
    Ok((value, idx))
}

fn parse_identifier(chars: &[char]) -> (String, usize) {
    let mut idx = 0usize;
    while idx < chars.len() && is_ident_continue(chars[idx]) {
        idx += 1;
    }
    (chars[..idx].iter().collect::<String>(), idx)
}

fn is_ident_start(ch: char) -> bool {
    ch.is_ascii_alphabetic() || ch == '_'
}

fn is_ident_continue(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn evaluate_budget_limits(ctx: &PolicyContext, bundle: &PolicyBundle) -> Option<PolicyDecision> {
    let session = &ctx.session;

    if let Some(limit) = bundle.budget_limits.max_tokens_per_session {
        if session.total_tokens > limit {
            return Some(block_decision(
                "budget_session_tokens_exceeded",
                "SessionTokenBudgetExceeded",
                RuleKind::System,
                Some("session.total_tokens > budget.max_tokens_per_session"),
                429,
                "Session token limit exceeded",
            ));
        }
    }

    if let Some(limit) = bundle.budget_limits.max_cost_usd_per_session {
        if f64::from(session.total_cost_usd) > limit {
            return Some(block_decision(
                "budget_session_cost_exceeded",
                "SessionCostBudgetExceeded",
                RuleKind::System,
                Some("session.total_cost_usd > budget.max_cost_usd_per_session"),
                429,
                "Session cost limit exceeded",
            ));
        }
    }

    if let Some(limit) = bundle.budget_limits.max_requests_per_session {
        if session.request_count > limit {
            return Some(block_decision(
                "budget_session_requests_exceeded",
                "SessionRequestBudgetExceeded",
                RuleKind::System,
                Some("session.request_count > budget.max_requests_per_session"),
                429,
                "Session request limit exceeded",
            ));
        }
    }

    None
}

fn evaluate_system_rules(
    normalized: &NormalizedRequest,
    artifacts: &[SensitiveArtifact],
) -> Option<PolicyDecision> {
    if has_private_key_artifact(artifacts) {
        return Some(block_decision(
            "sys_private_key_detected",
            "PrivateKeyDetected",
            RuleKind::System,
            Some("detect.private_key_detected == true"),
            403,
            "Private key detected in request",
        ));
    }

    if artifacts.len() > 50 {
        return Some(block_decision(
            "sys_artifact_count_exceeded",
            "ArtifactCountExceeded",
            RuleKind::System,
            Some("detect.artifact_count > 50"),
            403,
            "Artifact count exceeded system threshold",
        ));
    }

    if normalized.estimated_input_tokens > 2_000_000 {
        return Some(block_decision(
            "sys_input_tokens_exceeded",
            "InputTokensExceeded",
            RuleKind::System,
            Some("request.estimated_input_tokens > 2000000"),
            403,
            "Estimated input tokens exceeded system threshold",
        ));
    }

    None
}

fn evaluate_org_rules(
    normalized: &NormalizedRequest,
    artifacts: &[SensitiveArtifact],
    ctx: &PolicyContext,
    bundle: &PolicyBundle,
) -> (Option<PolicyDecision>, Vec<PolicyWarning>) {
    let mut warnings = Vec::new();
    let scope = build_eval_scope(normalized, artifacts, ctx, bundle);

    for rule in &bundle.org_rules.rules {
        match eval_rule_predicate(rule, &scope) {
            Ok(true) => {
                return (
                    Some(decision_from_rule(rule.rule_kind.clone(), rule)),
                    warnings,
                );
            }
            Ok(false) => {}
            Err(error) => warnings.push(PolicyWarning::RuleError {
                rule_id: rule.rule_id.clone(),
                error,
            }),
        }
    }

    (None, warnings)
}

struct EvalScope {
    values: HashMap<String, EvalValue>,
}

impl EvalScope {
    fn new() -> Self {
        Self {
            values: HashMap::new(),
        }
    }

    fn insert(&mut self, key: &str, value: EvalValue) {
        self.values.insert(key.to_string(), value);
    }

    fn get(&self, key: &str) -> Option<&EvalValue> {
        self.values.get(key)
    }
}

fn build_eval_scope(
    normalized: &NormalizedRequest,
    artifacts: &[SensitiveArtifact],
    ctx: &PolicyContext,
    bundle: &PolicyBundle,
) -> EvalScope {
    let mut scope = EvalScope::new();

    scope.insert(
        "request.provider",
        EvalValue::String(normalized.provider.clone()),
    );
    scope.insert(
        "request.model",
        normalized
            .model
            .as_ref()
            .map(|value| EvalValue::String(value.clone()))
            .unwrap_or(EvalValue::Null),
    );
    scope.insert(
        "request.endpoint_type",
        EvalValue::String(endpoint_type_label(normalized.endpoint_type).to_string()),
    );
    scope.insert("request.is_ai_call", EvalValue::Bool(normalized.is_ai_call));
    scope.insert("request.stream", EvalValue::Bool(normalized.stream));
    scope.insert(
        "request.has_tool_definitions",
        EvalValue::Bool(normalized.has_tool_definitions),
    );
    scope.insert(
        "request.estimated_input_tokens",
        EvalValue::Number(normalized.estimated_input_tokens as f64),
    );
    scope.insert(
        "request.estimated_cost_usd",
        EvalValue::Number(normalized.estimated_cost_usd),
    );
    scope.insert(
        "request.conversation_turn",
        normalized
            .conversation_turn
            .map(|value| EvalValue::Number(value as f64))
            .unwrap_or(EvalValue::Null),
    );
    scope.insert(
        "request.parse_confidence",
        EvalValue::String(parse_confidence_label(normalized.parse_confidence).to_string()),
    );
    scope.insert(
        "request.parse_source",
        EvalValue::String(parse_source_label(normalized.parse_source).to_string()),
    );

    let private_key_detected = has_private_key_artifact(artifacts);
    let credential_detected = has_credential_artifact(artifacts);
    let code_present = has_code_artifact(artifacts);
    let detected_languages = extract_detected_languages(artifacts);
    let max_severity = max_artifact_severity(artifacts);

    scope.insert(
        "detect.private_key_detected",
        EvalValue::Bool(private_key_detected),
    );
    scope.insert(
        "detect.credential_detected",
        EvalValue::Bool(credential_detected),
    );
    scope.insert("detect.code_present", EvalValue::Bool(code_present));
    scope.insert(
        "detect.detected_languages",
        EvalValue::Array(
            detected_languages
                .into_iter()
                .map(EvalValue::String)
                .collect::<Vec<_>>(),
        ),
    );
    scope.insert(
        "detect.artifact_count",
        EvalValue::Number(artifacts.len() as f64),
    );
    scope.insert(
        "detect.org_pattern_matches",
        EvalValue::Array(
            extract_org_pattern_matches(artifacts)
                .into_iter()
                .map(EvalValue::String)
                .collect::<Vec<_>>(),
        ),
    );
    scope.insert(
        "detect.max_severity",
        max_severity
            .map(EvalValue::String)
            .unwrap_or(EvalValue::Null),
    );

    scope.insert(
        "process.bundle_id",
        ctx.process_resolution
            .bundle_id
            .as_ref()
            .map(|value| EvalValue::String(value.clone()))
            .unwrap_or(EvalValue::Null),
    );
    scope.insert(
        "process.app_type",
        EvalValue::String(app_type_label(&ctx.process_resolution.app_type).to_string()),
    );
    scope.insert(
        "process.traffic_classification",
        EvalValue::String(traffic_classification_label(&ctx.traffic_classification).to_string()),
    );
    scope.insert(
        "process.process_name",
        ctx.process_resolution
            .process_name
            .as_ref()
            .map(|value| EvalValue::String(value.clone()))
            .unwrap_or(EvalValue::Null),
    );

    scope.insert(
        "deployment.model",
        EvalValue::String(deployment_model_label(&ctx.deployment).to_string()),
    );
    let (service_name, environment) = deployment_service_environment(&ctx.deployment);
    scope.insert(
        "deployment.service_name",
        service_name
            .map(EvalValue::String)
            .unwrap_or(EvalValue::Null),
    );
    scope.insert(
        "deployment.environment",
        environment
            .map(EvalValue::String)
            .unwrap_or(EvalValue::Null),
    );

    let total_tokens = ctx.session.total_tokens;
    let total_cost = ctx.session.total_cost_usd;
    let request_count = ctx.session.request_count;
    let credential_alerts = ctx.session.credential_alerts;
    scope.insert(
        "session.total_tokens",
        EvalValue::Number(total_tokens as f64),
    );
    scope.insert(
        "session.total_cost_usd",
        EvalValue::Number(f64::from(total_cost)),
    );
    scope.insert(
        "session.request_count",
        EvalValue::Number(request_count as f64),
    );
    scope.insert(
        "session.credential_alerts",
        EvalValue::Number(credential_alerts as f64),
    );

    scope.insert(
        "budget.max_tokens_per_session",
        bundle
            .budget_limits
            .max_tokens_per_session
            .map(|value| EvalValue::Number(value as f64))
            .unwrap_or(EvalValue::Null),
    );
    scope.insert(
        "budget.max_cost_usd_per_session",
        bundle
            .budget_limits
            .max_cost_usd_per_session
            .map(EvalValue::Number)
            .unwrap_or(EvalValue::Null),
    );
    scope.insert(
        "budget.max_requests_per_session",
        bundle
            .budget_limits
            .max_requests_per_session
            .map(|value| EvalValue::Number(value as f64))
            .unwrap_or(EvalValue::Null),
    );

    let semantic = ctx.semantic.as_ref();
    let semantic_use_case_label = semantic
        .map(|value| use_case_label(value.use_case_label).to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let semantic_use_case_confidence = semantic
        .map(|value| f64::from(value.use_case_confidence))
        .unwrap_or(0.0);
    let semantic_anomaly_score = semantic
        .map(|value| f64::from(value.anomaly_score))
        .unwrap_or(0.0);
    let semantic_anomaly_flags = semantic
        .map(|value| {
            value
                .anomaly_flags
                .iter()
                .map(|flag| EvalValue::String(anomaly_flag_label(flag).to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let semantic_complexity_score = semantic
        .map(|value| value.complexity_score as f64)
        .unwrap_or(0.0);
    let semantic_volatility_class = semantic
        .map(|value| volatility_class_label(value.volatility_class).to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let semantic_topic_cluster_id = semantic
        .map(|value| value.topic_cluster_id as f64)
        .unwrap_or(0.0);

    scope.insert("semantic.present", EvalValue::Bool(semantic.is_some()));
    scope.insert(
        "semantic.use_case_label",
        EvalValue::String(semantic_use_case_label.clone()),
    );
    scope.insert(
        "semantic.use_case_confidence",
        EvalValue::Number(semantic_use_case_confidence),
    );
    scope.insert(
        "semantic.anomaly_score",
        EvalValue::Number(semantic_anomaly_score),
    );
    scope.insert(
        "semantic.anomaly_flags",
        EvalValue::Array(semantic_anomaly_flags.clone()),
    );
    scope.insert(
        "semantic.complexity_score",
        EvalValue::Number(semantic_complexity_score),
    );
    scope.insert(
        "semantic.volatility_class",
        EvalValue::String(semantic_volatility_class.clone()),
    );
    scope.insert(
        "semantic.topic_cluster_id",
        EvalValue::Number(semantic_topic_cluster_id),
    );

    // Backward-compatible aliases for existing rule sets that referenced semantic fields
    // without a prefix.
    scope.insert("use_case_label", EvalValue::String(semantic_use_case_label));
    scope.insert(
        "use_case_confidence",
        EvalValue::Number(semantic_use_case_confidence),
    );
    scope.insert("anomaly_score", EvalValue::Number(semantic_anomaly_score));
    scope.insert("anomaly_flags", EvalValue::Array(semantic_anomaly_flags));
    scope.insert(
        "complexity_score",
        EvalValue::Number(semantic_complexity_score),
    );
    scope.insert(
        "volatility_class",
        EvalValue::String(semantic_volatility_class),
    );
    scope.insert(
        "topic_cluster_id",
        EvalValue::Number(semantic_topic_cluster_id),
    );

    scope
}

fn eval_rule_predicate(rule: &CompiledRule, scope: &EvalScope) -> Result<bool, String> {
    let result = eval_expr(&rule.compiled_expr, scope)?;
    match result {
        EvalValue::Bool(value) => Ok(value),
        other => Err(format!(
            "rule expression returned non-boolean value: {}",
            value_type_label(&other)
        )),
    }
}

fn eval_expr(expr: &CelExpr, scope: &EvalScope) -> Result<EvalValue, String> {
    match expr {
        CelExpr::Bool(value) => Ok(EvalValue::Bool(*value)),
        CelExpr::Number(value) => Ok(EvalValue::Number(*value)),
        CelExpr::String(value) => Ok(EvalValue::String(value.clone())),
        CelExpr::Null => Ok(EvalValue::Null),
        CelExpr::Field(path) => scope
            .get(path)
            .cloned()
            .ok_or_else(|| format!("unknown field path '{path}'")),
        CelExpr::Array(values) => {
            let mut out = Vec::with_capacity(values.len());
            for value in values {
                out.push(eval_expr(value, scope)?);
            }
            Ok(EvalValue::Array(out))
        }
        CelExpr::Not(value) => {
            let evaluated = eval_expr(value, scope)?;
            match evaluated {
                EvalValue::Bool(flag) => Ok(EvalValue::Bool(!flag)),
                other => Err(format!(
                    "logical not expects bool but got {}",
                    value_type_label(&other)
                )),
            }
        }
        CelExpr::And(lhs, rhs) => {
            let left = eval_expr(lhs, scope)?;
            match left {
                EvalValue::Bool(false) => Ok(EvalValue::Bool(false)),
                EvalValue::Bool(true) => match eval_expr(rhs, scope)? {
                    EvalValue::Bool(right) => Ok(EvalValue::Bool(right)),
                    other => Err(format!(
                        "logical and expects bool rhs but got {}",
                        value_type_label(&other)
                    )),
                },
                other => Err(format!(
                    "logical and expects bool lhs but got {}",
                    value_type_label(&other)
                )),
            }
        }
        CelExpr::Or(lhs, rhs) => {
            let left = eval_expr(lhs, scope)?;
            match left {
                EvalValue::Bool(true) => Ok(EvalValue::Bool(true)),
                EvalValue::Bool(false) => match eval_expr(rhs, scope)? {
                    EvalValue::Bool(right) => Ok(EvalValue::Bool(right)),
                    other => Err(format!(
                        "logical or expects bool rhs but got {}",
                        value_type_label(&other)
                    )),
                },
                other => Err(format!(
                    "logical or expects bool lhs but got {}",
                    value_type_label(&other)
                )),
            }
        }
        CelExpr::Eq(lhs, rhs) => {
            let left = eval_expr(lhs, scope)?;
            let right = eval_expr(rhs, scope)?;
            Ok(EvalValue::Bool(values_equal(&left, &right)))
        }
        CelExpr::Ne(lhs, rhs) => {
            let left = eval_expr(lhs, scope)?;
            let right = eval_expr(rhs, scope)?;
            Ok(EvalValue::Bool(!values_equal(&left, &right)))
        }
        CelExpr::Gt(lhs, rhs) => compare_numbers(lhs, rhs, scope, |a, b| a > b),
        CelExpr::Gte(lhs, rhs) => compare_numbers(lhs, rhs, scope, |a, b| a >= b),
        CelExpr::Lt(lhs, rhs) => compare_numbers(lhs, rhs, scope, |a, b| a < b),
        CelExpr::Lte(lhs, rhs) => compare_numbers(lhs, rhs, scope, |a, b| a <= b),
        CelExpr::Contains(collection, needle) => {
            let left = eval_expr(collection, scope)?;
            let right = eval_expr(needle, scope)?;
            match left {
                EvalValue::Array(values) => Ok(EvalValue::Bool(
                    values.iter().any(|value| values_equal(value, &right)),
                )),
                EvalValue::String(text) => {
                    if let EvalValue::String(fragment) = right {
                        Ok(EvalValue::Bool(text.contains(&fragment)))
                    } else {
                        Err("string.contains expects string argument".to_string())
                    }
                }
                other => Err(format!(
                    "contains expects array or string receiver but got {}",
                    value_type_label(&other)
                )),
            }
        }
    }
}

fn compare_numbers(
    lhs: &CelExpr,
    rhs: &CelExpr,
    scope: &EvalScope,
    compare: impl Fn(f64, f64) -> bool,
) -> Result<EvalValue, String> {
    let left = eval_expr(lhs, scope)?;
    let right = eval_expr(rhs, scope)?;
    let left_num = match left {
        EvalValue::Number(value) => value,
        other => {
            return Err(format!(
                "numeric comparison expects number lhs but got {}",
                value_type_label(&other)
            ));
        }
    };
    let right_num = match right {
        EvalValue::Number(value) => value,
        other => {
            return Err(format!(
                "numeric comparison expects number rhs but got {}",
                value_type_label(&other)
            ));
        }
    };
    Ok(EvalValue::Bool(compare(left_num, right_num)))
}

fn values_equal(left: &EvalValue, right: &EvalValue) -> bool {
    match (left, right) {
        (EvalValue::Bool(a), EvalValue::Bool(b)) => a == b,
        (EvalValue::Number(a), EvalValue::Number(b)) => (a - b).abs() <= f64::EPSILON,
        (EvalValue::String(a), EvalValue::String(b)) => a == b,
        (EvalValue::Array(a), EvalValue::Array(b)) => a == b,
        (EvalValue::Null, EvalValue::Null) => true,
        _ => false,
    }
}

fn value_type_label(value: &EvalValue) -> &'static str {
    match value {
        EvalValue::Bool(_) => "bool",
        EvalValue::Number(_) => "number",
        EvalValue::String(_) => "string",
        EvalValue::Array(_) => "array",
        EvalValue::Null => "null",
    }
}

fn decision_from_rule(rule_kind: RuleKind, rule: &CompiledRule) -> PolicyDecision {
    let kind = match &rule.action {
        RuleAction::Block { status, message } => PolicyDecisionKind::Block {
            status: *status,
            message: message.clone(),
        },
        RuleAction::Redact { targets } => PolicyDecisionKind::Redact {
            targets: targets.clone(),
        },
        RuleAction::Reroute { target } => PolicyDecisionKind::Reroute {
            target: target.clone(),
        },
        RuleAction::Flag { reason } => PolicyDecisionKind::Flag {
            reason: reason.clone(),
        },
    };

    PolicyDecision {
        kind,
        matched_rule: Some(MatchedRule {
            rule_id: rule.rule_id.clone(),
            rule_name: rule.rule_name.clone(),
            rule_kind,
            cel_expr: Some(rule.cel_expr.clone()),
        }),
        warnings: Vec::new(),
        eval_latency_us: 0,
    }
}

fn has_credential_artifact(artifacts: &[SensitiveArtifact]) -> bool {
    artifacts.iter().any(SensitiveArtifact::is_credential)
}

fn has_code_artifact(artifacts: &[SensitiveArtifact]) -> bool {
    artifacts
        .iter()
        .any(|artifact| matches!(artifact.kind, ArtifactKind::CodeBlock { .. }))
}

fn extract_detected_languages(artifacts: &[SensitiveArtifact]) -> Vec<String> {
    let mut out = Vec::new();
    for artifact in artifacts {
        if let ArtifactKind::CodeBlock { language } = &artifact.kind {
            let language = language.trim();
            if !language.is_empty() {
                out.push(language.to_string());
            }
        }
    }
    out
}

fn extract_org_pattern_matches(artifacts: &[SensitiveArtifact]) -> Vec<String> {
    let mut matches = artifacts
        .iter()
        .filter_map(|artifact| {
            if let ArtifactKind::OrgPattern { pattern_id } = &artifact.kind {
                Some(pattern_id.to_string())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    matches.sort();
    matches.dedup();
    matches
}

fn max_artifact_severity(artifacts: &[SensitiveArtifact]) -> Option<String> {
    let mut best: Option<(String, u8)> = None;
    for artifact in artifacts {
        let (sev, rank) = match artifact.severity {
            soth_core::artifacts::ArtifactSeverity::Critical => ("critical", 4),
            soth_core::artifacts::ArtifactSeverity::High => ("high", 3),
            soth_core::artifacts::ArtifactSeverity::Medium => ("medium", 2),
            soth_core::artifacts::ArtifactSeverity::Low => ("low", 1),
        };
        let rank = match rank {
            4 | 3 | 2 | 1 => rank,
            _ => 0,
        };
        if rank == 0 {
            continue;
        }
        let should_replace = match best {
            Some((_, existing_rank)) => rank > existing_rank,
            None => true,
        };
        if should_replace {
            best = Some((sev.to_string(), rank));
        }
    }
    best.map(|(label, _)| label)
}

fn app_type_label(value: &AppType) -> &'static str {
    match value {
        AppType::Host => "host",
        AppType::NonHost => "non_host",
        AppType::Unknown => "unknown",
    }
}

fn traffic_classification_label(value: &TrafficClassification) -> &'static str {
    match value {
        TrafficClassification::ToolUsage => "tool_usage",
        TrafficClassification::UnknownAgent => "unknown_agent",
        TrafficClassification::ApplicationUsage => "application_usage",
        TrafficClassification::Other => "other",
    }
}

fn deployment_model_label(value: &DeploymentModel) -> &'static str {
    match value {
        DeploymentModel::Proxy => "proxy",
        DeploymentModel::Sidecar { .. } => "sidecar",
        DeploymentModel::Sdk { .. } => "sdk",
    }
}

fn endpoint_type_label(value: EndpointType) -> &'static str {
    match value {
        EndpointType::ChatCompletion => "chat_completion",
        EndpointType::TextCompletion => "text_completion",
        EndpointType::Embedding => "embedding",
        EndpointType::ImageGeneration => "image_generation",
        EndpointType::AudioTranscription => "audio_transcription",
        EndpointType::FunctionCall => "function_call",
        EndpointType::Streaming => "streaming",
        EndpointType::Unknown => "unknown",
    }
}

fn parse_confidence_label(value: soth_core::ParseConfidence) -> &'static str {
    match value {
        soth_core::ParseConfidence::Full => "full",
        soth_core::ParseConfidence::Partial => "partial",
        soth_core::ParseConfidence::Heuristic => "heuristic",
    }
}

fn parse_source_label(value: soth_core::ParseSource) -> &'static str {
    match value {
        soth_core::ParseSource::Rest { .. } => "rest",
        soth_core::ParseSource::GraphQl => "graphql",
        soth_core::ParseSource::Grpc => "grpc",
        soth_core::ParseSource::JsonRpc => "jsonrpc",
        soth_core::ParseSource::AgentApp => "agent_app",
        soth_core::ParseSource::Heuristic => "heuristic",
        soth_core::ParseSource::Filtered => "filtered",
    }
}

fn use_case_label(value: UseCaseLabel) -> &'static str {
    match value {
        UseCaseLabel::CodeGeneration => "code_generation",
        UseCaseLabel::CodeReview => "code_review",
        UseCaseLabel::CodeDebugging => "code_debugging",
        UseCaseLabel::CodeRefactor => "code_refactor",
        UseCaseLabel::TextSummarization => "text_summarization",
        UseCaseLabel::TextGeneration => "text_generation",
        UseCaseLabel::Translation => "translation",
        UseCaseLabel::DataAnalysis => "data_analysis",
        UseCaseLabel::DataExtraction => "data_extraction",
        UseCaseLabel::QuestionAnswering => "question_answering",
        UseCaseLabel::DocumentSearch => "document_search",
        UseCaseLabel::AgentTask => "agent_task",
        UseCaseLabel::ToolOrchestration => "tool_orchestration",
        UseCaseLabel::ImageAnalysis => "image_analysis",
        UseCaseLabel::AudioTranscription => "audio_transcription",
        UseCaseLabel::SystemPromptOnly => "system_prompt_only",
        UseCaseLabel::Unknown => "unknown",
    }
}

fn anomaly_flag_label(value: &AnomalyFlag) -> &'static str {
    match value {
        AnomalyFlag::TopicDrift => "topic_drift",
        AnomalyFlag::CredentialBurst => "credential_burst",
        AnomalyFlag::TokenBurst => "token_burst",
        AnomalyFlag::ModelSwitch => "model_switch",
        AnomalyFlag::AgentLoopPattern => "agent_loop_pattern",
        AnomalyFlag::RapidFireRequests => "rapid_fire_requests",
        AnomalyFlag::UnusualSystemPromptChange => "unusual_system_prompt_change",
        AnomalyFlag::ToolCallDepthSpike => "tool_call_depth_spike",
    }
}

fn volatility_class_label(value: VolatilityClass) -> &'static str {
    match value {
        VolatilityClass::Static => "static",
        VolatilityClass::LowVolatile => "low_volatile",
        VolatilityClass::Dynamic => "dynamic",
        VolatilityClass::HighlyDynamic => "highly_dynamic",
    }
}

fn deployment_service_environment(value: &DeploymentModel) -> (Option<String>, Option<String>) {
    match value {
        DeploymentModel::Proxy => (None, None),
        DeploymentModel::Sidecar {
            service_name,
            environment,
        }
        | DeploymentModel::Sdk {
            service_name,
            environment,
        } => (Some(service_name.clone()), Some(environment.clone())),
    }
}

fn has_private_key_artifact(artifacts: &[SensitiveArtifact]) -> bool {
    artifacts.iter().any(SensitiveArtifact::is_private_key)
}

fn allow_decision() -> PolicyDecision {
    PolicyDecision {
        kind: PolicyDecisionKind::Allow,
        matched_rule: None,
        warnings: Vec::new(),
        eval_latency_us: 0,
    }
}

fn block_decision(
    rule_id: &str,
    rule_name: &str,
    rule_kind: RuleKind,
    cel_expr: Option<&str>,
    status: u16,
    message: &str,
) -> PolicyDecision {
    PolicyDecision {
        kind: PolicyDecisionKind::Block {
            status,
            message: message.to_string(),
        },
        matched_rule: Some(MatchedRule {
            rule_id: rule_id.to_string(),
            rule_name: rule_name.to_string(),
            rule_kind,
            cel_expr: cel_expr.map(|value| value.to_string()),
        }),
        warnings: Vec::new(),
        eval_latency_us: 0,
    }
}

fn with_latency(mut decision: PolicyDecision, started: Instant) -> PolicyDecision {
    decision.eval_latency_us = started.elapsed().as_micros() as u64;
    decision
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use soth_core::{
        ArtifactKind, ArtifactLocation, ArtifactSeverity, CaptureMode,
        EndpointType, FormatMetadata, ParseConfidence, ParseSource, ProcessMatchKind,
        ProcessResolution, SessionSnapshot as SessionBudget,
    };

    fn signed_bundle_bytes(payload: PolicyBundlePayload) -> Vec<u8> {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let payload_bytes = match serde_json::to_vec(&payload) {
            Ok(bytes) => bytes,
            Err(error) => panic!("serialize payload failed: {error}"),
        };
        let signature = key.sign(&payload_bytes);
        let envelope = SignedPolicyBundle {
            payload,
            signature: B64.encode(signature.to_bytes()),
            public_key: B64.encode(key.verifying_key().to_bytes()),
        };
        match serde_json::to_vec(&envelope) {
            Ok(bytes) => bytes,
            Err(error) => panic!("serialize envelope failed: {error}"),
        }
    }

    fn fixture_payload(rule_expr: &str) -> PolicyBundlePayload {
        PolicyBundlePayload {
            metadata: PolicyBundleMetadata {
                bundle_version: "2026.02.25-test".to_string(),
                schema_version: "1".to_string(),
                org_id: "demo-org".to_string(),
                signed_at: 1_772_000_000,
            },
            system_rules: vec![RuleDefinition {
                rule_id: "sys_private_key".to_string(),
                rule_name: "PrivateKey".to_string(),
                cel_expr: rule_expr.to_string(),
                action: RuleAction::Block {
                    status: 403,
                    message: "blocked".to_string(),
                },
            }],
            org_rules: Vec::new(),
            org_patterns: OrgPatterns::default(),
            budget_limits: BudgetLimits::default(),
        }
    }

    fn org_rule(rule_id: &str, expr: &str, action: RuleAction) -> RuleDefinition {
        RuleDefinition {
            rule_id: rule_id.to_string(),
            rule_name: rule_id.to_string(),
            cel_expr: expr.to_string(),
            action,
        }
    }

    fn fixture_payload_with_org_rules(org_rules: Vec<RuleDefinition>) -> PolicyBundlePayload {
        let mut payload = fixture_payload("detect.private_key_detected == true");
        payload.org_rules = org_rules;
        payload
    }

    fn fixture_request() -> NormalizedRequest {
        NormalizedRequest {
            parse_confidence: ParseConfidence::Full,
            parser_id: "sync-policy-test".to_string(),
            schema_version: "1".to_string(),
            parse_warnings: Vec::new(),
            is_ai_call: true,
            provider: "anthropic".to_string(),
            model: Some("claude-3-5-sonnet-20241022".to_string()),
            endpoint_type: EndpointType::ChatCompletion,
            api_version: None,
            system_prompt_hash: None,
            system_prompt_token_estimate: None,
            user_content_hash: "user-hash".to_string(),
            user_content_token_estimate: 64,
            conversation_hash: "conv-hash".to_string(),
            conversation_turn: Some(1),
            stream: false,
            has_tool_definitions: false,
            tool_definition_hash: None,
            temperature: None,
            max_tokens: None,
            top_p: None,
            stop_sequences: Vec::new(),
            estimated_input_tokens: 128,
            estimated_cost_usd: 0.04,
            parse_source: ParseSource::GraphQl,
            canonical_cache_key: String::new(),
            format_metadata: FormatMetadata::Unknown { method: String::new(), path: String::new() },
            has_structured_output: false,
            has_tool_results: false,
            estimated_output_tokens: None,
            user_prompt: None,
        }
    }

    fn fixture_context(session: Option<SessionBudget>) -> PolicyContext {
        PolicyContext {
            process_resolution: ProcessResolution {
                match_kind: ProcessMatchKind::Unknown,
                bundle_id: None,
                app_type: AppType::Unknown,
                capture_mode: None,
                process_name: None,
                matched_app_id: None,
                ..Default::default()
            },
            capture_mode: CaptureMode::MetadataOnly,
            traffic_classification: TrafficClassification::ToolUsage,
            deployment: DeploymentModel::Proxy,
            skip_org_rules: false,
            semantic: None,
            session: session.unwrap_or_default(),
        }
    }

    fn fixture_semantic_context() -> soth_core::SemanticPolicyContext {
        soth_core::SemanticPolicyContext {
            use_case_label: soth_core::UseCaseLabel::CodeGeneration,
            use_case_confidence: 0.94,
            anomaly_score: 0.87,
            anomaly_flags: vec![soth_core::AnomalyFlag::TokenBurst],
            complexity_score: 4,
            volatility_class: soth_core::VolatilityClass::Dynamic,
            topic_cluster_id: 42,
        }
    }

    fn artifact(kind: ArtifactKind, severity: ArtifactSeverity) -> SensitiveArtifact {
        SensitiveArtifact {
            kind,
            severity,
            location: ArtifactLocation::Unknown,
            commitment: None,
            redacted_hint: None,
        }
    }

    fn assert_block_rule(decision: &PolicyDecision, expected_rule_id: &str) {
        assert!(matches!(decision.kind, PolicyDecisionKind::Block { .. }));
        let matched = match decision.matched_rule.as_ref() {
            Some(value) => value,
            None => panic!("expected matched rule"),
        };
        assert_eq!(matched.rule_id, expected_rule_id);
    }

    fn assert_decision_eq_ignoring_latency(left: &PolicyDecision, right: &PolicyDecision) {
        assert_eq!(left.kind, right.kind);
        assert_eq!(left.matched_rule, right.matched_rule);
        assert_eq!(left.warnings, right.warnings);
    }

    #[test]
    fn rejects_invalid_signature() {
        let payload = fixture_payload("detect.private_key_detected == true");
        let mut bytes = signed_bundle_bytes(payload);

        if let Some(last) = bytes.last_mut() {
            *last = if *last == b'a' { b'b' } else { b'a' };
        }

        match load_bundle_from_bytes(&bytes) {
            Err(PolicyBundleError::InvalidJson(_))
            | Err(PolicyBundleError::InvalidSignature(_)) => {}
            other => panic!("expected signature or json error, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_cel_expression() {
        let payload = fixture_payload("request.provider ==");
        let bytes = signed_bundle_bytes(payload);
        match load_bundle_from_bytes(&bytes) {
            Err(PolicyBundleError::InvalidRule { .. }) => {}
            other => panic!("expected invalid rule error, got: {other:?}"),
        }
    }

    #[test]
    fn evaluate_stub_allows() {
        let payload = fixture_payload("detect.private_key_detected == true");
        let bytes = signed_bundle_bytes(payload);
        let bundle = match load_bundle_from_bytes(&bytes) {
            Ok(bundle) => bundle,
            Err(error) => panic!("bundle should load: {error}"),
        };

        let normalized = fixture_request();
        let ctx = fixture_context(None);

        let out = evaluate(&normalized, &[], &ctx, &bundle);
        assert!(matches!(out.kind, PolicyDecisionKind::Allow));
    }

    #[test]
    fn phase2_budget_token_limit_blocks() {
        let mut payload = fixture_payload("detect.private_key_detected == true");
        payload.budget_limits.max_tokens_per_session = Some(1000);
        let bundle = match load_bundle_from_bytes(&signed_bundle_bytes(payload)) {
            Ok(bundle) => bundle,
            Err(error) => panic!("bundle should load: {error}"),
        };
        let normalized = fixture_request();
        let ctx = fixture_context(Some(SessionBudget {
            total_tokens: 1001,
            total_cost_usd: 0.0,
            request_count: 1,
            credential_alerts: 0,
            ..Default::default()
        }));

        let out = evaluate(&normalized, &[], &ctx, &bundle);
        assert_block_rule(&out, "budget_session_tokens_exceeded");
    }

    #[test]
    fn phase2_budget_cost_limit_blocks() {
        let mut payload = fixture_payload("detect.private_key_detected == true");
        payload.budget_limits.max_cost_usd_per_session = Some(2.0);
        let bundle = match load_bundle_from_bytes(&signed_bundle_bytes(payload)) {
            Ok(bundle) => bundle,
            Err(error) => panic!("bundle should load: {error}"),
        };
        let normalized = fixture_request();
        let ctx = fixture_context(Some(SessionBudget {
            total_tokens: 0,
            total_cost_usd: 2.01,
            request_count: 1,
            credential_alerts: 0,
            ..Default::default()
        }));

        let out = evaluate(&normalized, &[], &ctx, &bundle);
        assert_block_rule(&out, "budget_session_cost_exceeded");
    }

    #[test]
    fn phase2_budget_request_limit_blocks() {
        let mut payload = fixture_payload("detect.private_key_detected == true");
        payload.budget_limits.max_requests_per_session = Some(50);
        let bundle = match load_bundle_from_bytes(&signed_bundle_bytes(payload)) {
            Ok(bundle) => bundle,
            Err(error) => panic!("bundle should load: {error}"),
        };
        let normalized = fixture_request();
        let ctx = fixture_context(Some(SessionBudget {
            total_tokens: 0,
            total_cost_usd: 0.0,
            request_count: 51,
            credential_alerts: 0,
            ..Default::default()
        }));

        let out = evaluate(&normalized, &[], &ctx, &bundle);
        assert_block_rule(&out, "budget_session_requests_exceeded");
    }

    #[test]
    fn phase2_system_private_key_blocks() {
        let payload = fixture_payload("detect.private_key_detected == true");
        let bundle = match load_bundle_from_bytes(&signed_bundle_bytes(payload)) {
            Ok(bundle) => bundle,
            Err(error) => panic!("bundle should load: {error}"),
        };
        let normalized = fixture_request();
        let ctx = fixture_context(None);
        let artifacts = vec![artifact(
            ArtifactKind::PrivateKey,
            ArtifactSeverity::Critical,
        )];

        let out = evaluate(&normalized, &artifacts, &ctx, &bundle);
        assert_block_rule(&out, "sys_private_key_detected");
    }

    #[test]
    fn phase2_system_artifact_count_blocks() {
        let payload = fixture_payload("detect.private_key_detected == true");
        let bundle = match load_bundle_from_bytes(&signed_bundle_bytes(payload)) {
            Ok(bundle) => bundle,
            Err(error) => panic!("bundle should load: {error}"),
        };
        let normalized = fixture_request();
        let ctx = fixture_context(None);
        let artifacts = (0..51)
            .map(|_| artifact(ArtifactKind::UnknownCredential, ArtifactSeverity::Low))
            .collect::<Vec<_>>();

        let out = evaluate(&normalized, &artifacts, &ctx, &bundle);
        assert_block_rule(&out, "sys_artifact_count_exceeded");
    }

    #[test]
    fn phase2_system_input_tokens_blocks() {
        let payload = fixture_payload("detect.private_key_detected == true");
        let bundle = match load_bundle_from_bytes(&signed_bundle_bytes(payload)) {
            Ok(bundle) => bundle,
            Err(error) => panic!("bundle should load: {error}"),
        };
        let mut normalized = fixture_request();
        normalized.estimated_input_tokens = 2_000_001;
        let ctx = fixture_context(None);

        let out = evaluate(&normalized, &[], &ctx, &bundle);
        assert_block_rule(&out, "sys_input_tokens_exceeded");
    }

    #[test]
    fn phase2_budget_precedes_system_rules() {
        let mut payload = fixture_payload("detect.private_key_detected == true");
        payload.budget_limits.max_tokens_per_session = Some(1000);
        let bundle = match load_bundle_from_bytes(&signed_bundle_bytes(payload)) {
            Ok(bundle) => bundle,
            Err(error) => panic!("bundle should load: {error}"),
        };
        let normalized = fixture_request();
        let ctx = fixture_context(Some(SessionBudget {
            total_tokens: 1001,
            total_cost_usd: 0.0,
            request_count: 1,
            credential_alerts: 0,
            ..Default::default()
        }));
        let artifacts = vec![artifact(
            ArtifactKind::PrivateKey,
            ArtifactSeverity::Critical,
        )];

        let out = evaluate(&normalized, &artifacts, &ctx, &bundle);
        assert_block_rule(&out, "budget_session_tokens_exceeded");
    }

    #[test]
    fn phase3_org_rules_first_match_wins() {
        let payload = fixture_payload_with_org_rules(vec![
            org_rule(
                "org_flag_first",
                "request.provider == \"anthropic\"",
                RuleAction::Flag {
                    reason: "first".to_string(),
                },
            ),
            org_rule(
                "org_block_second",
                "request.provider == \"anthropic\"",
                RuleAction::Block {
                    status: 403,
                    message: "should_not_fire".to_string(),
                },
            ),
        ]);

        let bundle = match load_bundle_from_bytes(&signed_bundle_bytes(payload)) {
            Ok(bundle) => bundle,
            Err(error) => panic!("bundle should load: {error}"),
        };

        let out = evaluate(&fixture_request(), &[], &fixture_context(None), &bundle);
        assert!(matches!(out.kind, PolicyDecisionKind::Flag { .. }));
        let matched = match out.matched_rule.as_ref() {
            Some(value) => value,
            None => panic!("expected matched rule"),
        };
        assert_eq!(matched.rule_id, "org_flag_first");
    }

    #[test]
    fn phase3_skip_org_rules_bypasses_org_loop() {
        let payload = fixture_payload_with_org_rules(vec![org_rule(
            "org_block",
            "request.provider == \"anthropic\"",
            RuleAction::Block {
                status: 403,
                message: "blocked".to_string(),
            },
        )]);
        let bundle = match load_bundle_from_bytes(&signed_bundle_bytes(payload)) {
            Ok(bundle) => bundle,
            Err(error) => panic!("bundle should load: {error}"),
        };

        let mut ctx = fixture_context(None);
        ctx.skip_org_rules = true;

        let out = evaluate(&fixture_request(), &[], &ctx, &bundle);
        assert!(matches!(out.kind, PolicyDecisionKind::Allow));
        assert!(out.matched_rule.is_none());
    }

    #[test]
    fn phase3_runtime_error_skips_rule_and_continues() {
        let payload = fixture_payload_with_org_rules(vec![
            org_rule(
                "org_bad_type",
                "request.model > 1",
                RuleAction::Block {
                    status: 403,
                    message: "bad".to_string(),
                },
            ),
            org_rule(
                "org_good_rule",
                "request.provider == \"anthropic\"",
                RuleAction::Block {
                    status: 403,
                    message: "blocked".to_string(),
                },
            ),
        ]);

        let bundle = match load_bundle_from_bytes(&signed_bundle_bytes(payload)) {
            Ok(bundle) => bundle,
            Err(error) => panic!("bundle should load: {error}"),
        };

        let out = evaluate(&fixture_request(), &[], &fixture_context(None), &bundle);
        assert_block_rule(&out, "org_good_rule");
        assert!(out
            .warnings
            .iter()
            .any(|warning| matches!(warning, PolicyWarning::RuleError { rule_id, .. } if rule_id == "org_bad_type")));
    }

    #[test]
    fn phase3_org_redact_action() {
        let payload = fixture_payload_with_org_rules(vec![org_rule(
            "org_redact",
            "request.provider == \"anthropic\"",
            RuleAction::Redact {
                targets: vec![RedactTarget {
                    field_path: "messages[*].content".to_string(),
                    artifact_type: "credential".to_string(),
                }],
            },
        )]);

        let bundle = match load_bundle_from_bytes(&signed_bundle_bytes(payload)) {
            Ok(bundle) => bundle,
            Err(error) => panic!("bundle should load: {error}"),
        };

        let out = evaluate(&fixture_request(), &[], &fixture_context(None), &bundle);
        assert!(matches!(out.kind, PolicyDecisionKind::Redact { .. }));
        let matched = match out.matched_rule.as_ref() {
            Some(value) => value,
            None => panic!("expected matched rule"),
        };
        assert_eq!(matched.rule_id, "org_redact");
    }

    #[test]
    fn phase3_org_reroute_action() {
        let payload = fixture_payload_with_org_rules(vec![org_rule(
            "org_reroute",
            "request.estimated_cost_usd > 0.01",
            RuleAction::Reroute {
                target: RerouteTarget {
                    provider: "anthropic".to_string(),
                    model: "claude-3-haiku-20240307".to_string(),
                    reason: "cost control".to_string(),
                },
            },
        )]);

        let bundle = match load_bundle_from_bytes(&signed_bundle_bytes(payload)) {
            Ok(bundle) => bundle,
            Err(error) => panic!("bundle should load: {error}"),
        };

        let out = evaluate(&fixture_request(), &[], &fixture_context(None), &bundle);
        assert!(matches!(out.kind, PolicyDecisionKind::Reroute { .. }));
        let matched = match out.matched_rule.as_ref() {
            Some(value) => value,
            None => panic!("expected matched rule"),
        };
        assert_eq!(matched.rule_id, "org_reroute");
    }

    #[test]
    fn phase3_org_contains_with_array() {
        let payload = fixture_payload_with_org_rules(vec![org_rule(
            "org_allowlist_block",
            "![\"anthropic\", \"openai\"].contains(request.provider)",
            RuleAction::Block {
                status: 403,
                message: "provider not allowed".to_string(),
            },
        )]);

        let bundle = match load_bundle_from_bytes(&signed_bundle_bytes(payload)) {
            Ok(bundle) => bundle,
            Err(error) => panic!("bundle should load: {error}"),
        };

        let out = evaluate(&fixture_request(), &[], &fixture_context(None), &bundle);
        assert!(matches!(out.kind, PolicyDecisionKind::Allow));
    }

    #[test]
    fn phase3_semantic_context_fields_are_available_to_org_rules() {
        let payload = fixture_payload_with_org_rules(vec![org_rule(
            "org_semantic_block",
            "semantic.use_case_label == \"code_generation\" && semantic.anomaly_flags.contains(\"token_burst\") && semantic.topic_cluster_id == 42",
            RuleAction::Block {
                status: 403,
                message: "semantic policy block".to_string(),
            },
        )]);

        let bundle = match load_bundle_from_bytes(&signed_bundle_bytes(payload)) {
            Ok(bundle) => bundle,
            Err(error) => panic!("bundle should load: {error}"),
        };

        let mut ctx = fixture_context(None);
        ctx.semantic = Some(fixture_semantic_context());

        let out = evaluate(&fixture_request(), &[], &ctx, &bundle);
        assert_block_rule(&out, "org_semantic_block");
    }

    #[test]
    fn phase3_org_pattern_matches_are_exposed_from_artifacts() {
        let payload = fixture_payload_with_org_rules(vec![org_rule(
            "org_pattern_block",
            "detect.org_pattern_matches.contains(\"7\")",
            RuleAction::Block {
                status: 403,
                message: "org pattern matched".to_string(),
            },
        )]);
        let bundle = match load_bundle_from_bytes(&signed_bundle_bytes(payload)) {
            Ok(bundle) => bundle,
            Err(error) => panic!("bundle should load: {error}"),
        };

        let artifacts = vec![artifact(
            ArtifactKind::OrgPattern { pattern_id: 7 },
            ArtifactSeverity::High,
        )];
        let out = evaluate(
            &fixture_request(),
            &artifacts,
            &fixture_context(None),
            &bundle,
        );
        assert_block_rule(&out, "org_pattern_block");
    }

    #[test]
    fn phase3_semantic_alias_fields_remain_backward_compatible() {
        let payload = fixture_payload_with_org_rules(vec![org_rule(
            "org_semantic_alias_block",
            "use_case_label == \"code_generation\" && anomaly_score > 0.8",
            RuleAction::Block {
                status: 403,
                message: "semantic alias block".to_string(),
            },
        )]);

        let bundle = match load_bundle_from_bytes(&signed_bundle_bytes(payload)) {
            Ok(bundle) => bundle,
            Err(error) => panic!("bundle should load: {error}"),
        };

        let mut ctx = fixture_context(None);
        ctx.semantic = Some(fixture_semantic_context());
        let blocked = evaluate(&fixture_request(), &[], &ctx, &bundle);
        assert_block_rule(&blocked, "org_semantic_alias_block");

        ctx.semantic = None;
        let allowed = evaluate(&fixture_request(), &[], &ctx, &bundle);
        assert!(matches!(allowed.kind, PolicyDecisionKind::Allow));
        assert!(allowed.warnings.is_empty());
    }

    #[test]
    fn phase4_determinism_fixture_matrix() {
        let payload = fixture_payload_with_org_rules(vec![
            org_rule(
                "org_tool_flag",
                "request.provider == \"anthropic\" && request.has_tool_definitions == true",
                RuleAction::Flag {
                    reason: "tool traffic".to_string(),
                },
            ),
            org_rule(
                "org_block_unknown_agent_with_credential",
                "process.traffic_classification == \"unknown_agent\" && detect.credential_detected == true",
                RuleAction::Block {
                    status: 403,
                    message: "blocked".to_string(),
                },
            ),
            org_rule(
                "org_high_cost_reroute",
                "request.estimated_cost_usd > 0.2",
                RuleAction::Reroute {
                    target: RerouteTarget {
                        provider: "anthropic".to_string(),
                        model: "claude-3-haiku-20240307".to_string(),
                        reason: "cost".to_string(),
                    },
                },
            ),
        ]);

        let bundle = match load_bundle_from_bytes(&signed_bundle_bytes(payload)) {
            Ok(bundle) => bundle,
            Err(error) => panic!("bundle should load: {error}"),
        };

        let fixtures = vec![
            {
                let mut req = fixture_request();
                req.has_tool_definitions = true;
                (req, Vec::new(), fixture_context(None))
            },
            {
                let mut ctx = fixture_context(None);
                ctx.traffic_classification = TrafficClassification::UnknownAgent;
                (
                    fixture_request(),
                    vec![artifact(
                        ArtifactKind::UnknownCredential,
                        ArtifactSeverity::High,
                    )],
                    ctx,
                )
            },
            {
                let mut req = fixture_request();
                req.has_tool_definitions = false;
                req.estimated_cost_usd = 0.31;
                (req, Vec::new(), fixture_context(None))
            },
            {
                let mut req = fixture_request();
                req.provider = "openai".to_string();
                req.has_tool_definitions = false;
                req.estimated_cost_usd = 0.02;
                (req, Vec::new(), fixture_context(None))
            },
        ];

        for (request, artifacts, context) in fixtures {
            let left = evaluate(&request, &artifacts, &context, &bundle);
            let right = evaluate(&request, &artifacts, &context, &bundle);
            assert_decision_eq_ignoring_latency(&left, &right);
        }
    }

    #[test]
    fn phase4_fuzz_no_panic() {
        let payload = fixture_payload_with_org_rules(vec![
            org_rule(
                "org_basic",
                "request.is_ai_call == true && request.provider != \"forbidden\"",
                RuleAction::Flag {
                    reason: "ai".to_string(),
                },
            ),
            org_rule(
                "org_runtime_error",
                "request.model > 1",
                RuleAction::Block {
                    status: 403,
                    message: "bad".to_string(),
                },
            ),
            org_rule(
                "org_contains",
                "[\"tool_usage\", \"application_usage\"].contains(process.traffic_classification)",
                RuleAction::Flag {
                    reason: "classified".to_string(),
                },
            ),
        ]);
        let bundle = match load_bundle_from_bytes(&signed_bundle_bytes(payload)) {
            Ok(bundle) => bundle,
            Err(error) => panic!("bundle should load: {error}"),
        };

        let mut rng = StdRng::seed_from_u64(42);
        let provider_pool = ["anthropic", "openai", "gemini", "cohere", "unknown"];
        let artifact_pool = [
            ArtifactKind::PrivateKey,
            ArtifactKind::UnknownCredential,
            ArtifactKind::CodeBlock {
                language: "rust".to_string(),
            },
            ArtifactKind::CodeBlock {
                language: "python".to_string(),
            },
            ArtifactKind::Jwt,
            ArtifactKind::AuthLogic,
        ];
        let severity_pool = [
            ArtifactSeverity::Critical,
            ArtifactSeverity::High,
            ArtifactSeverity::Medium,
            ArtifactSeverity::Low,
        ];

        for _ in 0..2000 {
            let mut request = fixture_request();
            request.provider = provider_pool[rng.gen_range(0..provider_pool.len())].to_string();
            request.model = if rng.gen_bool(0.3) {
                None
            } else {
                Some(format!("model-{}", rng.gen_range(0..100)))
            };
            request.endpoint_type = if rng.gen_bool(0.5) {
                EndpointType::ChatCompletion
            } else {
                EndpointType::TextCompletion
            };
            request.is_ai_call = rng.gen_bool(0.8);
            request.stream = rng.gen_bool(0.5);
            request.has_tool_definitions = rng.gen_bool(0.5);
            request.estimated_input_tokens = rng.gen_range(0..2_500_000);
            request.estimated_cost_usd = rng.gen_range(0.0..1.0);
            request.conversation_turn = if rng.gen_bool(0.4) {
                None
            } else {
                Some(rng.gen_range(0..20))
            };
            request.parse_confidence = if rng.gen_bool(0.7) {
                ParseConfidence::Full
            } else {
                ParseConfidence::Heuristic
            };
            request.parse_source = ParseSource::Heuristic;

            let artifact_count = rng.gen_range(0..60);
            let mut artifacts = Vec::with_capacity(artifact_count);
            for _ in 0..artifact_count {
                artifacts.push(SensitiveArtifact {
                    kind: artifact_pool[rng.gen_range(0..artifact_pool.len())].clone(),
                    severity: severity_pool[rng.gen_range(0..severity_pool.len())],
                    location: ArtifactLocation::Unknown,
                    commitment: None,
                    redacted_hint: None,
                });
            }

            let mut ctx = fixture_context(if rng.gen_bool(0.7) {
                Some(SessionBudget {
                    total_tokens: rng.gen_range(0..600_000),
                    total_cost_usd: rng.gen_range(0.0..200.0),
                    request_count: rng.gen_range(0..500),
                    credential_alerts: rng.gen_range(0..50),
                    ..Default::default()
                })
            } else {
                None
            });
            ctx.traffic_classification = match rng.gen_range(0..4) {
                0 => TrafficClassification::ToolUsage,
                1 => TrafficClassification::UnknownAgent,
                2 => TrafficClassification::ApplicationUsage,
                _ => TrafficClassification::Other,
            };

            let result = std::panic::catch_unwind(|| evaluate(&request, &artifacts, &ctx, &bundle));
            assert!(result.is_ok(), "evaluate panicked for fuzz case");
        }
    }

    #[test]
    fn phase4_evaluate_entrypoint_no_io_tokens() {
        let source = include_str!("sync_policy.rs");
        let start = match source.find("pub fn evaluate(") {
            Some(index) => index,
            None => panic!("evaluate function not found in source"),
        };
        let end = match source.find("pub fn warm(") {
            Some(index) => index,
            None => panic!("warm function not found in source"),
        };
        let body = &source[start..end];

        let forbidden = [
            "std::fs",
            "std::net",
            "tokio::",
            "thread::spawn",
            "std::process",
            "reqwest",
        ];
        for needle in forbidden {
            assert!(
                !body.contains(needle),
                "evaluate contains forbidden token: {needle}"
            );
        }
    }

    #[test]
    fn phase4_latency_smoke_100_rules() {
        let mut rules = Vec::new();
        for idx in 0..100 {
            let expr = if idx == 99 {
                "request.provider == \"anthropic\""
            } else {
                "request.provider == \"non_match\""
            };
            rules.push(org_rule(
                &format!("org_{idx}"),
                expr,
                RuleAction::Flag {
                    reason: "bench".to_string(),
                },
            ));
        }

        let payload = fixture_payload_with_org_rules(rules);
        let bundle = match load_bundle_from_bytes(&signed_bundle_bytes(payload)) {
            Ok(bundle) => bundle,
            Err(error) => panic!("bundle should load: {error}"),
        };
        let request = fixture_request();
        let context = fixture_context(None);

        let iterations = 5000usize;
        let mut samples = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let started = Instant::now();
            let _ = evaluate(&request, &[], &context, &bundle);
            samples.push(started.elapsed().as_micros() as u64);
        }

        samples.sort_unstable();
        let idx = |q: f64| -> usize {
            let raw = ((samples.len().saturating_sub(1) as f64) * q).ceil() as usize;
            raw.min(samples.len().saturating_sub(1))
        };
        let p95 = samples[idx(0.95)];
        let p99 = samples[idx(0.99)];

        assert!(p95 < 3_000, "p95 latency {}us exceeded 3000us target", p95);
        assert!(p99 < 5_000, "p99 latency {}us exceeded 5000us target", p99);
    }
}
