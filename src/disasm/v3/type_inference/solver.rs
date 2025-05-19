//! Type inference solver implementation.

use crate::disasm::v3::model::{Model, TypeInferenceComplete};
use crate::disasm::v3::type_inference::TypeInferenceResult;
use crate::disasm::Error;

/// Solver for type inference.
pub struct Solver {
    /// The model containing the folded SSA result.
    model: Model<crate::disasm::v3::model::FoldedSsaComplete>,
}

impl Solver {
    /// Create a new solver.
    pub fn new(model: Model<crate::disasm::v3::model::FoldedSsaComplete>) -> Self {
        Self { model }
    }

    /// Run the solver to produce a type inference result.
    pub fn run(model: Model<crate::disasm::v3::model::FoldedSsaComplete>) -> Result<Model<TypeInferenceComplete>, Error> {
        let solver = Self::new(model);
        solver.solve()
    }

    /// Solve the type inference problem.
    fn solve(self) -> Result<Model<TypeInferenceComplete>, Error> {
        // Create an empty result
        let result = TypeInferenceResult::new();

        // Return a new model with the type inference result
        Ok(self.model.with_type_inference_result(result))
    }
}