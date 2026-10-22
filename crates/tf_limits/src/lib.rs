//! Shared safety ceilings and cumulative allowances. No input formats or evaluator dependencies.
use std::cell::Cell;
use std::fmt;
use std::num::NonZeroU64;

pub mod input;

pub const PARSE_DEPTH_MAX: usize = 64;
pub const AST_DEPTH_MAX: usize = 64;
pub const JSON_DEPTH_MAX: usize = 64;
pub const EVALUATION_DEPTH_MAX: usize = 128;
pub const ALTERNATIVES_MAX: usize = 16;
pub const PRODUCT_ROWS_MAX: usize = 4096;
pub const PRODUCT_VALUES_MAX: usize = 65_536;
pub const INDENT_BYTES_MAX: usize = 1 << 20;
pub const MODULE_DEPTH_MAX: usize = 10;
pub const EXPANSION_MAX: usize = 64;
pub const INSTANCES_MAX: usize = 16_384;
pub const WORKERS_MAX: usize = 64;

/// Evaluation/conversion entries, collection copies, traversal and template work per root.
/// This is a work count, not a bound on CPU instructions or allocated bytes.
pub const EVALUATION_STEPS_DEFAULT: u64 = 1_000_000;
/// Default evaluation and conversion during module composition, per root.
pub const LOADER_STEPS_DEFAULT: u64 = 1_000_000;
/// Hook dispatch and counted rule/interpreter operations per root.
/// About 147 times the largest measured corpus root; see docs/LIMITS.md.
pub const RULE_STEPS_DEFAULT: u64 = 10_000_000;
/// Cooperative elapsed execution allowance shared by Rego calls in one root.
pub const REGO_TIME_MS_DEFAULT: u64 = 10_000;

pub const INPUT_BYTES_DEFAULT: u64 = 16 * 1024 * 1024;
pub const SOURCE_BYTES_DEFAULT: u64 = 256 * 1024 * 1024;
pub const FILE_ENTRIES_DEFAULT: u64 = 16_384;
pub const DIRECTORY_ENTRIES_DEFAULT: u64 = 262_144;
pub const ROOTS_DEFAULT: u64 = 4096;
pub const ARENA_BYTES_DEFAULT: u64 = 256 * 1024 * 1024;
pub const COLLECTION_BYTES_DEFAULT: u64 = 256 * 1024 * 1024;
pub const TEXT_BYTES_DEFAULT: u64 = 256 * 1024 * 1024;
pub const AST_NODES_DEFAULT: u64 = 4_000_000;
/// Findings plus rule errors per scan. Both scale with rules × resources.
/// About 190 times the largest measured corpus scan; see docs/LIMITS.md.
pub const RESULTS_DEFAULT: u64 = 100_000;

const _: () = assert!(JSON_DEPTH_MAX <= AST_DEPTH_MAX);
const _: () = assert!(PRODUCT_ROWS_MAX <= PRODUCT_VALUES_MAX);
const _: () = assert!(INDENT_BYTES_MAX < u32::MAX as usize);

/// Validated allowances. Fixed stack safety ceilings cannot be raised by configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    evaluation_steps: NonZeroU64,
    loader_steps: NonZeroU64,
    rule_steps: NonZeroU64,
    rego_time_ms: NonZeroU64,
    input_bytes: NonZeroU64,
    source_bytes: NonZeroU64,
    file_entries: NonZeroU64,
    directory_entries: NonZeroU64,
    roots: NonZeroU64,
    arena_bytes: NonZeroU64,
    ast_nodes: NonZeroU64,
    text_bytes: NonZeroU64,
    collection_bytes: NonZeroU64,
    results: NonZeroU64,
}

impl Limits {
    pub fn new(evaluation_steps: u64) -> Result<Self, InvalidLimits> {
        let evaluation_steps =
            NonZeroU64::new(evaluation_steps).ok_or(InvalidLimits("evaluation_steps"))?;
        Ok(Self {
            evaluation_steps,
            loader_steps: NonZeroU64::new(LOADER_STEPS_DEFAULT).expect("positive default"),
            rule_steps: NonZeroU64::new(RULE_STEPS_DEFAULT).expect("positive default"),
            rego_time_ms: NonZeroU64::new(REGO_TIME_MS_DEFAULT).expect("positive default"),
            input_bytes: NonZeroU64::new(INPUT_BYTES_DEFAULT).expect("positive default"),
            source_bytes: NonZeroU64::new(SOURCE_BYTES_DEFAULT).expect("positive default"),
            file_entries: NonZeroU64::new(FILE_ENTRIES_DEFAULT).expect("positive default"),
            directory_entries: NonZeroU64::new(DIRECTORY_ENTRIES_DEFAULT)
                .expect("positive default"),
            roots: NonZeroU64::new(ROOTS_DEFAULT).expect("positive default"),
            arena_bytes: NonZeroU64::new(ARENA_BYTES_DEFAULT).expect("positive default"),
            ast_nodes: NonZeroU64::new(AST_NODES_DEFAULT).expect("positive default"),
            text_bytes: NonZeroU64::new(TEXT_BYTES_DEFAULT).expect("positive default"),
            collection_bytes: NonZeroU64::new(COLLECTION_BYTES_DEFAULT).expect("positive default"),
            results: NonZeroU64::new(RESULTS_DEFAULT).expect("positive default"),
        })
    }

    pub fn with_evaluation_steps(mut self, steps: u64) -> Result<Self, InvalidLimits> {
        self.evaluation_steps = NonZeroU64::new(steps).ok_or(InvalidLimits("evaluation_steps"))?;
        Ok(self)
    }

    pub fn evaluation_steps(self) -> u64 {
        self.evaluation_steps.get()
    }

    pub fn with_loader_steps(mut self, steps: u64) -> Result<Self, InvalidLimits> {
        self.loader_steps = NonZeroU64::new(steps).ok_or(InvalidLimits("loader_steps"))?;
        Ok(self)
    }

    pub fn loader_steps(self) -> u64 {
        self.loader_steps.get()
    }

    pub fn with_rule_steps(mut self, steps: u64) -> Result<Self, InvalidLimits> {
        self.rule_steps = NonZeroU64::new(steps).ok_or(InvalidLimits("rule_steps"))?;
        Ok(self)
    }

    pub fn rule_steps(self) -> u64 {
        self.rule_steps.get()
    }

    pub fn with_rego_time_ms(mut self, value: u64) -> Result<Self, InvalidLimits> {
        self.rego_time_ms = NonZeroU64::new(value).ok_or(InvalidLimits("rego_time_ms"))?;
        Ok(self)
    }

    pub fn rego_time_ms(self) -> u64 {
        self.rego_time_ms.get()
    }
    pub fn with_input_bytes(mut self, value: u64) -> Result<Self, InvalidLimits> {
        if value > u64::from(u32::MAX) {
            return Err(InvalidLimits("input_bytes (maximum 4294967295)"));
        }
        self.input_bytes = NonZeroU64::new(value).ok_or(InvalidLimits("input_bytes"))?;
        Ok(self)
    }

    pub fn input_bytes(self) -> u64 {
        self.input_bytes.get()
    }

    pub fn with_source_bytes(mut self, value: u64) -> Result<Self, InvalidLimits> {
        self.source_bytes = NonZeroU64::new(value).ok_or(InvalidLimits("source_bytes"))?;
        Ok(self)
    }

    pub fn source_bytes(self) -> u64 {
        self.source_bytes.get()
    }

    pub fn with_file_entries(mut self, value: u64) -> Result<Self, InvalidLimits> {
        if value > u64::from(u32::MAX) {
            return Err(InvalidLimits("file_entries (maximum 4294967295)"));
        }
        self.file_entries = NonZeroU64::new(value).ok_or(InvalidLimits("file_entries"))?;
        Ok(self)
    }

    pub fn file_entries(self) -> u64 {
        self.file_entries.get()
    }

    pub fn with_directory_entries(mut self, value: u64) -> Result<Self, InvalidLimits> {
        self.directory_entries =
            NonZeroU64::new(value).ok_or(InvalidLimits("directory_entries"))?;
        Ok(self)
    }

    pub fn directory_entries(self) -> u64 {
        self.directory_entries.get()
    }

    pub fn with_roots(mut self, value: u64) -> Result<Self, InvalidLimits> {
        self.roots = NonZeroU64::new(value).ok_or(InvalidLimits("roots"))?;
        Ok(self)
    }

    pub fn roots(self) -> u64 {
        self.roots.get()
    }

    pub fn with_arena_bytes(mut self, value: u64) -> Result<Self, InvalidLimits> {
        self.arena_bytes = NonZeroU64::new(value).ok_or(InvalidLimits("arena_bytes"))?;
        Ok(self)
    }

    pub fn arena_bytes(self) -> u64 {
        self.arena_bytes.get()
    }

    pub fn with_ast_nodes(mut self, value: u64) -> Result<Self, InvalidLimits> {
        self.ast_nodes = NonZeroU64::new(value).ok_or(InvalidLimits("ast_nodes"))?;
        Ok(self)
    }

    pub fn with_text_bytes(mut self, value: u64) -> Result<Self, InvalidLimits> {
        self.text_bytes = NonZeroU64::new(value).ok_or(InvalidLimits("text_bytes"))?;
        Ok(self)
    }

    pub fn text_bytes(self) -> u64 {
        self.text_bytes.get()
    }

    pub fn with_collection_bytes(mut self, value: u64) -> Result<Self, InvalidLimits> {
        self.collection_bytes = NonZeroU64::new(value).ok_or(InvalidLimits("collection_bytes"))?;
        Ok(self)
    }

    pub fn collection_bytes(self) -> u64 {
        self.collection_bytes.get()
    }

    pub fn with_results(mut self, value: u64) -> Result<Self, InvalidLimits> {
        self.results = NonZeroU64::new(value).ok_or(InvalidLimits("results"))?;
        Ok(self)
    }

    pub fn results(self) -> u64 {
        self.results.get()
    }

    pub fn ast_nodes(self) -> u64 {
        self.ast_nodes.get()
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::new(EVALUATION_STEPS_DEFAULT).expect("the default allowance is positive")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidLimits(&'static str);

impl fmt::Display for InvalidLimits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} must be a positive integer", self.0)
    }
}

impl std::error::Error for InvalidLimits {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resource {
    EvaluationSteps,
    LoaderSteps,
    RuleSteps,
    RegoTimeMs,
    InputBytes,
    SourceBytes,
    FileEntries,
    DirectoryEntries,
    Roots,
    ArenaBytes,
    AstNodes,
    TextBytes,
    CollectionBytes,
    Results,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Exhaustion {
    pub resource: Resource,
    pub allowance: u64,
}

impl fmt::Display for Exhaustion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Bumpalo reports the same error for its ceiling and the backing allocator.
        // Successful charges need not have reached the ceiling when allocation is refused.
        if matches!(
            self.resource,
            Resource::ArenaBytes | Resource::TextBytes | Resource::CollectionBytes
        ) {
            return write!(
                f,
                "{} allocation refused within scan allowance {}",
                if self.resource == Resource::ArenaBytes {
                    "arena_bytes"
                } else if self.resource == Resource::TextBytes {
                    "text_bytes"
                } else {
                    "collection_bytes"
                },
                self.allowance
            );
        }
        let resource = match self.resource {
            Resource::EvaluationSteps => "evaluation_steps",
            Resource::LoaderSteps => "loader_steps",
            Resource::RuleSteps => "rule_steps",
            Resource::RegoTimeMs => "rego_time_ms",
            Resource::InputBytes => "input_bytes",
            Resource::SourceBytes => "source_bytes",
            Resource::FileEntries => "file_entries",
            Resource::DirectoryEntries => "directory_entries",
            Resource::Roots => "roots",
            Resource::ArenaBytes => "arena_bytes",
            Resource::AstNodes => "ast_nodes",
            Resource::TextBytes => "text_bytes",
            Resource::CollectionBytes => "collection_bytes",
            Resource::Results => "results",
        };
        let scope = match self.resource {
            Resource::EvaluationSteps
            | Resource::LoaderSteps
            | Resource::RuleSteps
            | Resource::RegoTimeMs => "root",
            Resource::InputBytes => "input",
            _ => "scan",
        };
        write!(f, "{resource} exceeds {scope} allowance {}", self.allowance)
    }
}

impl std::error::Error for Exhaustion {}

impl From<Exhaustion> for std::io::Error {
    fn from(error: Exhaustion) -> Self {
        Self::other(error)
    }
}

/// Owned by one root, shared by reference with every evaluator in that root.
/// Charging is monotonic; failure is sticky and cannot refund or wrap the counter.
#[derive(Debug)]
pub struct WorkBudget {
    limits: Limits,
    resource: Resource,
    used: Cell<u64>,
    exhausted: Cell<Option<Exhaustion>>,
}

impl WorkBudget {
    pub fn new(limits: Limits) -> Self {
        Self::for_resource(limits, Resource::EvaluationSteps)
    }

    pub fn for_resource(limits: Limits, resource: Resource) -> Self {
        Self {
            limits,
            resource,
            used: Cell::new(0),
            exhausted: Cell::new(None),
        }
    }

    fn allowance(&self) -> u64 {
        match self.resource {
            Resource::EvaluationSteps => self.limits.evaluation_steps(),
            Resource::LoaderSteps => self.limits.loader_steps(),
            Resource::RuleSteps => self.limits.rule_steps(),
            _ => panic!("scan storage resources use InputBudget"),
        }
    }

    /// Zero once exhausted.
    pub fn remaining(&self) -> u64 {
        if self.exhausted.get().is_some() {
            return 0;
        }
        self.allowance() - self.used.get()
    }

    pub fn charge(&self, steps: u64) -> Result<(), Exhaustion> {
        let used = self.used.get();
        let allowance = self.allowance();
        assert!(used <= allowance);
        if let Some(exhaustion) = self.exhausted.get() {
            return Err(exhaustion);
        }
        if steps > allowance - used {
            let exhaustion = Exhaustion {
                resource: self.resource,
                allowance,
            };
            self.exhausted.set(Some(exhaustion));
            return Err(exhaustion);
        }
        self.used.set(used + steps);
        assert!(self.used.get() <= allowance);
        Ok(())
    }

    pub fn used(&self) -> u64 {
        self.used.get()
    }

    pub fn exhaustion(&self) -> Option<Exhaustion> {
        self.exhausted.get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_and_exhaustion_are_monotonic() {
        assert!(Limits::new(0).is_err());
        let budget = WorkBudget::new(Limits::new(3).unwrap());
        assert_eq!(budget.charge(2), Ok(()));
        assert_eq!(budget.charge(1), Ok(()));
        let failure = budget.charge(1).unwrap_err();
        assert_eq!(failure.allowance, 3);
        assert_eq!(budget.used(), 3);
        assert_eq!(budget.charge(0), Err(failure));
        assert_eq!(budget.charge(1), Err(failure));
    }

    #[test]
    fn results_are_counted_independently_of_storage_exhaustion() {
        assert!(Limits::default().with_results(0).is_err());
        let budget = input::InputBudget::new(Limits::default().with_results(2).unwrap());
        assert!(budget.admit_collection(u64::MAX).is_err());
        assert!(budget.exhaustion().is_some());
        assert_eq!(budget.admit_result(), Ok(()));
        assert_eq!(budget.admit_result(), Ok(()));
        assert_eq!(budget.results_exhaustion(), None);
        let refused = budget.admit_result().unwrap_err();
        assert_eq!(refused.resource, Resource::Results);
        assert_eq!(refused.to_string(), "results exceeds scan allowance 2");
        assert_eq!(budget.results_exhaustion(), Some(refused));
        assert_eq!(budget.admit_result(), Err(refused));
        assert_eq!(budget.stats().results, 2);
        assert_eq!(
            budget.exhaustion().unwrap().resource,
            Resource::CollectionBytes
        );
    }

    #[test]
    fn charges_cannot_overflow() {
        let budget = WorkBudget::new(Limits::new(u64::MAX).unwrap());
        assert_eq!(budget.charge(u64::MAX - 1), Ok(()));
        assert!(budget.charge(2).is_err());
        assert_eq!(budget.used(), u64::MAX - 1);
        let fresh = WorkBudget::new(Limits::new(1).unwrap());
        assert_eq!(fresh.charge(1), Ok(()));
        assert_eq!(fresh.exhaustion(), None);
    }

    #[test]
    fn loader_allowance_is_validated_and_independent() {
        assert!(Limits::default().with_loader_steps(0).is_err());
        let limits = Limits::new(1).unwrap().with_loader_steps(3).unwrap();
        let loader = WorkBudget::for_resource(limits, Resource::LoaderSteps);
        assert_eq!(loader.charge(3), Ok(()));
        let exhausted = loader.charge(1).unwrap_err();
        assert_eq!(exhausted.resource, Resource::LoaderSteps);
        assert_eq!(exhausted.allowance, 3);
        assert_eq!(WorkBudget::new(limits).charge(1), Ok(()));
    }

    #[test]
    fn rule_allowance_is_independent_and_cannot_wrap() {
        assert!(Limits::default().with_rule_steps(0).is_err());
        let limits = Limits::new(1).unwrap().with_rule_steps(u64::MAX).unwrap();
        let rules = WorkBudget::for_resource(limits, Resource::RuleSteps);
        assert_eq!(rules.charge(u64::MAX - 1), Ok(()));
        let exhausted = rules.charge(2).unwrap_err();
        assert_eq!(exhausted.resource, Resource::RuleSteps);
        assert_eq!(exhausted.allowance, u64::MAX);
        assert_eq!(rules.used(), u64::MAX - 1);
        assert_eq!(rules.charge(0), Err(exhausted));
        assert_eq!(WorkBudget::new(limits).charge(1), Ok(()));
        assert_eq!(
            WorkBudget::for_resource(limits, Resource::LoaderSteps).charge(1),
            Ok(())
        );
    }
}
