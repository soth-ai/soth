#[derive(Debug, Clone)]
pub struct ClassifyConfig {
    pub embedding_enabled: bool,
    pub anomaly_enabled: bool,
    pub lsh_near_dupe_threshold: u32,
    pub complexity_weights: ComplexityWeights,
    pub volatility: VolatilityConfig,
}

#[derive(Debug, Clone)]
pub struct ComplexityWeights {
    pub token_weight: f32,
    pub tool_count_weight: f32,
    pub turn_depth_weight: f32,
    pub structured_output_weight: f32,
}

#[derive(Debug, Clone)]
pub struct VolatilityConfig {
    pub temporal_keywords: Vec<String>,
    pub pronoun_keywords: Vec<String>,
    pub static_threshold: f32,
    pub low_volatile_threshold: f32,
    pub dynamic_threshold: f32,
}

impl Default for ClassifyConfig {
    fn default() -> Self {
        Self {
            embedding_enabled: true,
            anomaly_enabled: true,
            lsh_near_dupe_threshold: 8,
            complexity_weights: ComplexityWeights {
                token_weight: 0.40,
                tool_count_weight: 0.25,
                turn_depth_weight: 0.25,
                structured_output_weight: 0.10,
            },
            volatility: VolatilityConfig::default(),
        }
    }
}

impl Default for VolatilityConfig {
    fn default() -> Self {
        Self {
            temporal_keywords: vec![
                "today".to_string(),
                "now".to_string(),
                "latest".to_string(),
                "current".to_string(),
                "recently".to_string(),
                "this week".to_string(),
                "right now".to_string(),
                "as of".to_string(),
            ],
            pronoun_keywords: vec![
                "my ".to_string(),
                "i ".to_string(),
                "me ".to_string(),
                "our ".to_string(),
                "we ".to_string(),
                "you ".to_string(),
            ],
            static_threshold: 0.10,
            low_volatile_threshold: 0.35,
            dynamic_threshold: 0.70,
        }
    }
}
