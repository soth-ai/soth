use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectedProvider {
    Anthropic,
    OpenAi,
    AzureOpenAi,
    Gemini,
    Cohere,
    Bedrock,
    Mistral,
    Groq,
    Together,
    Fireworks,
    Ollama,
    VLlm,
    LmStudio,
    VertexAi,
    Unknown,
}

impl Default for DetectedProvider {
    fn default() -> Self {
        Self::Unknown
    }
}

impl DetectedProvider {
    pub fn canonical_name(&self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::OpenAi => "openai",
            Self::AzureOpenAi => "azure_openai",
            Self::Gemini => "gemini",
            Self::Cohere => "cohere",
            Self::Bedrock => "bedrock",
            Self::Mistral => "mistral",
            Self::Groq => "groq",
            Self::Together => "together",
            Self::Fireworks => "fireworks",
            Self::Ollama => "ollama",
            Self::VLlm => "vllm",
            Self::LmStudio => "lmstudio",
            Self::VertexAi => "vertex_ai",
            Self::Unknown => "unknown",
        }
    }

    pub fn input_cost_per_mtok(&self, model: &str) -> Option<f32> {
        let model = model.to_ascii_lowercase();
        match self {
            Self::OpenAi => {
                if model.starts_with("gpt-4o") {
                    Some(5.0)
                } else if model.starts_with("gpt-4.1") {
                    Some(2.0)
                } else if model.starts_with("gpt-4") {
                    Some(10.0)
                } else if model.starts_with("gpt-3.5") {
                    Some(0.5)
                } else {
                    None
                }
            }
            Self::Anthropic => {
                if model.contains("opus") {
                    Some(15.0)
                } else if model.contains("sonnet") {
                    Some(3.0)
                } else if model.contains("haiku") {
                    Some(0.8)
                } else {
                    None
                }
            }
            Self::Gemini => {
                if model.contains("2.0") || model.contains("1.5") {
                    Some(1.0)
                } else {
                    None
                }
            }
            Self::Cohere => {
                if model.contains("command") {
                    Some(3.0)
                } else {
                    None
                }
            }
            Self::Mistral => {
                if model.contains("large") {
                    Some(8.0)
                } else {
                    Some(0.25)
                }
            }
            Self::Groq => Some(0.59),
            Self::Together => Some(0.8),
            Self::Fireworks => Some(0.9),
            Self::Bedrock | Self::VertexAi => None,
            Self::Ollama | Self::VLlm | Self::LmStudio => Some(0.0),
            Self::AzureOpenAi => {
                if model.starts_with("gpt-4") {
                    Some(10.0)
                } else {
                    None
                }
            }
            Self::Unknown => None,
        }
    }

    pub fn output_cost_per_mtok(&self, model: &str) -> Option<f32> {
        let model = model.to_ascii_lowercase();
        match self {
            Self::OpenAi => {
                if model.starts_with("gpt-4o") {
                    Some(15.0)
                } else if model.starts_with("gpt-4.1") {
                    Some(8.0)
                } else if model.starts_with("gpt-4") {
                    Some(30.0)
                } else if model.starts_with("gpt-3.5") {
                    Some(1.5)
                } else {
                    None
                }
            }
            Self::Anthropic => {
                if model.contains("opus") {
                    Some(75.0)
                } else if model.contains("sonnet") {
                    Some(15.0)
                } else if model.contains("haiku") {
                    Some(4.0)
                } else {
                    None
                }
            }
            Self::Gemini => {
                if model.contains("2.0") || model.contains("1.5") {
                    Some(3.0)
                } else {
                    None
                }
            }
            Self::Cohere => {
                if model.contains("command") {
                    Some(15.0)
                } else {
                    None
                }
            }
            Self::Mistral => {
                if model.contains("large") {
                    Some(24.0)
                } else {
                    Some(0.75)
                }
            }
            Self::Groq => Some(0.79),
            Self::Together => Some(1.2),
            Self::Fireworks => Some(1.8),
            Self::Bedrock | Self::VertexAi => None,
            Self::Ollama | Self::VLlm | Self::LmStudio => Some(0.0),
            Self::AzureOpenAi => {
                if model.starts_with("gpt-4") {
                    Some(30.0)
                } else {
                    None
                }
            }
            Self::Unknown => None,
        }
    }
}
