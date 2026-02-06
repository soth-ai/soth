//! Beautiful session name generator
//!
//! Generates human-readable session names using adjective-noun pairs
//! like "brave-tiger" or "happy-dolphin".

use rand::seq::SliceRandom;
use rand::thread_rng;

/// Adjectives for name generation
const ADJECTIVES: &[&str] = &[
    "agile", "bold", "brave", "bright", "calm",
    "clever", "cool", "cosmic", "crisp", "curious",
    "dapper", "daring", "deft", "eager", "elegant",
    "epic", "fast", "fearless", "fierce", "fluffy",
    "gentle", "gleaming", "golden", "graceful", "grand",
    "happy", "hidden", "honest", "humble", "icy",
    "jade", "jolly", "keen", "kind", "lively",
    "lucky", "lunar", "magic", "merry", "mighty",
    "misty", "noble", "peaceful", "playful", "polite",
    "proud", "quick", "quiet", "rapid", "ruby",
    "rustic", "serene", "sharp", "shiny", "silent",
    "silver", "sleek", "smart", "smooth", "snowy",
    "solar", "sonic", "speedy", "steady", "stellar",
    "stormy", "sunny", "super", "swift", "tender",
    "tidy", "tiny", "topaz", "tranquil", "turbo",
    "vivid", "warm", "wild", "winter", "witty",
    "young", "zesty", "zippy",
];

/// Nouns for name generation (animals)
const NOUNS: &[&str] = &[
    "alpaca", "badger", "bear", "beaver", "buffalo",
    "camel", "cheetah", "cobra", "coyote", "crane",
    "deer", "dolphin", "dragon", "eagle", "elephant",
    "falcon", "ferret", "finch", "fox", "gazelle",
    "gecko", "giraffe", "goose", "gorilla", "hawk",
    "heron", "husky", "jaguar", "koala", "lemur",
    "leopard", "lion", "llama", "lynx", "mantis",
    "moose", "mouse", "narwhal", "otter", "owl",
    "panda", "panther", "parrot", "pelican", "penguin",
    "phoenix", "pigeon", "pony", "puma", "python",
    "rabbit", "raccoon", "raven", "reindeer", "rhino",
    "robin", "salmon", "seal", "shark", "sparrow",
    "spider", "squirrel", "stork", "swan", "tiger",
    "toucan", "turtle", "unicorn", "viper", "walrus",
    "whale", "wolf", "wombat", "yak", "zebra",
];

/// Generate a random beautiful session name
pub fn generate_session_name() -> String {
    let mut rng = thread_rng();
    let adjective = ADJECTIVES.choose(&mut rng).unwrap_or(&"happy");
    let noun = NOUNS.choose(&mut rng).unwrap_or(&"penguin");
    format!("{}-{}", adjective, noun)
}

/// Generate a deterministic name from a seed (e.g., session ID)
pub fn generate_name_from_seed(seed: &str) -> String {
    // Use a simple hash to derive indices
    let hash = seed.bytes().fold(0u64, |acc, b| {
        acc.wrapping_mul(31).wrapping_add(b as u64)
    });

    let adj_idx = (hash % ADJECTIVES.len() as u64) as usize;
    let noun_idx = ((hash / ADJECTIVES.len() as u64) % NOUNS.len() as u64) as usize;

    format!(
        "{}-{}",
        ADJECTIVES[adj_idx],
        NOUNS[noun_idx]
    )
}

/// Generate multiple unique names
pub fn generate_unique_names(count: usize) -> Vec<String> {
    let mut names = std::collections::HashSet::new();
    let mut rng = thread_rng();

    while names.len() < count {
        let adjective = ADJECTIVES.choose(&mut rng).unwrap_or(&"happy");
        let noun = NOUNS.choose(&mut rng).unwrap_or(&"penguin");
        names.insert(format!("{}-{}", adjective, noun));
    }

    names.into_iter().collect()
}

/// Name generator with configurable word lists
#[derive(Debug, Clone)]
pub struct NameGenerator {
    adjectives: Vec<String>,
    nouns: Vec<String>,
}

impl Default for NameGenerator {
    fn default() -> Self {
        Self {
            adjectives: ADJECTIVES.iter().map(|s| (*s).to_string()).collect(),
            nouns: NOUNS.iter().map(|s| (*s).to_string()).collect(),
        }
    }
}

impl NameGenerator {
    /// Create a new name generator
    pub fn new() -> Self {
        Self::default()
    }

    /// Add custom adjectives
    pub fn with_adjectives(mut self, adjectives: Vec<String>) -> Self {
        self.adjectives = adjectives;
        self
    }

    /// Add custom nouns
    pub fn with_nouns(mut self, nouns: Vec<String>) -> Self {
        self.nouns = nouns;
        self
    }

    /// Generate a random name
    pub fn generate(&self) -> String {
        let mut rng = thread_rng();
        let adjective = self.adjectives.choose(&mut rng)
            .map(|s| s.as_str())
            .unwrap_or("happy");
        let noun = self.nouns.choose(&mut rng)
            .map(|s| s.as_str())
            .unwrap_or("penguin");
        format!("{}-{}", adjective, noun)
    }

    /// Generate a name from a seed
    pub fn generate_from_seed(&self, seed: &str) -> String {
        let hash = seed.bytes().fold(0u64, |acc, b| {
            acc.wrapping_mul(31).wrapping_add(b as u64)
        });

        let adj_idx = (hash % self.adjectives.len() as u64) as usize;
        let noun_idx = ((hash / self.adjectives.len() as u64) % self.nouns.len() as u64) as usize;

        format!(
            "{}-{}",
            self.adjectives[adj_idx],
            self.nouns[noun_idx]
        )
    }

    /// Get the total number of possible combinations
    pub fn combinations(&self) -> usize {
        self.adjectives.len() * self.nouns.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_session_name() {
        let name = generate_session_name();
        assert!(name.contains('-'));
        let parts: Vec<&str> = name.split('-').collect();
        assert_eq!(parts.len(), 2);
        assert!(!parts[0].is_empty());
        assert!(!parts[1].is_empty());
    }

    #[test]
    fn test_generate_name_from_seed() {
        let name1 = generate_name_from_seed("test-seed-123");
        let name2 = generate_name_from_seed("test-seed-123");
        let name3 = generate_name_from_seed("different-seed");

        // Same seed should produce same name
        assert_eq!(name1, name2);

        // Different seeds should (usually) produce different names
        // Not guaranteed but highly likely
        assert!(name1.contains('-'));
        assert!(name3.contains('-'));
    }

    #[test]
    fn test_generate_unique_names() {
        let names = generate_unique_names(10);
        assert_eq!(names.len(), 10);

        // All names should be unique
        let unique: std::collections::HashSet<_> = names.iter().collect();
        assert_eq!(unique.len(), 10);
    }

    #[test]
    fn test_name_generator() {
        let generator = NameGenerator::new();
        let name = generator.generate();
        assert!(name.contains('-'));

        // Should have many combinations
        assert!(generator.combinations() > 1000);
    }

    #[test]
    fn test_name_generator_from_seed() {
        let generator = NameGenerator::new();
        let name1 = generator.generate_from_seed("my-session-id");
        let name2 = generator.generate_from_seed("my-session-id");

        assert_eq!(name1, name2);
    }

    #[test]
    fn test_custom_word_lists() {
        let generator = NameGenerator::new()
            .with_adjectives(vec!["red".to_string(), "blue".to_string()])
            .with_nouns(vec!["cat".to_string(), "dog".to_string()]);

        assert_eq!(generator.combinations(), 4);

        let name = generator.generate();
        let parts: Vec<&str> = name.split('-').collect();
        assert!(["red", "blue"].contains(&parts[0]));
        assert!(["cat", "dog"].contains(&parts[1]));
    }
}
