use itertools::Itertools;

use super::{
    types::{Type, TypeVarId},
    InferenceAlgorithmState,
};

use crate::disasm::{
    symbol_renaming::StructId,
    v3::{
        define_id_type, lir::Expression, ssa::SsaMemoryReference,
        type_inference::type_bounds_map::TypeVarRegistry, FunctionId, InstructionId,
    },
};
use std::{
    collections::{HashMap, HashSet},
    fmt,
}; // Assuming types.rs is in the parent module (type_inference)

define_id_type!(ConstraintId);

/// Describes the reason a type constraint was generated.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConstraintReason {
    // General
    Assignment,               // target = src  => type(src) <: type(target)
    TypeVariableSubstitution, // TypeVar(X) used where TypeVar(Y) is expected, etc.
    PhiNodeOperand,           // Incoming value to a PHI node: type(incoming) <: type(phi_dest)

    // Literals
    NumericLiteral, // A literal number implies Int type, e.g. `5` => TypeVar(N) <: Int
    LiteralBoolean, // A literal boolean (true/false, or 0/1 if distinguished) => TypeVar(N) <: Bool
    // LiteralTruthy might be derived via Bool <: Truthy, so not strictly needed here.

    // Control Flow
    IfConditionOperand, // `if cond ...` => type(cond) <: Truthy

    // Function Calls & Returns
    FunctionCallImpliesFunctionType, // `f(...)` => type(f) <: Function { params: FreshTV, returns: FreshTV }
    FunctionCallArguments, // binds call site arguments to the local function call signature.
    FunctionCallReturns, // binds the return value of a function call to the return type of the function.
    CalleeFunctionArguments, // callee argument binding
    CalleeFunctionReturns, // callee return type binding
    FunctionCallArgumentsBinding,
    FunctionCallReturnsBinding,
    ConstIsFunctionPointer,
    ReturnStatement, // `return expr;` => type(expr) <: function_return_type

    // Pointer Operations
    DereferenceRequiresPointer, // `*ptr_expr` (read context) => type(ptr_expr) <: Pointer(FreshTV for pointee)
    AssignmentToDereferenceTarget, // `*ptr_expr = src` => type(ptr_expr) <: Pointer(type(src))

    // Tuples
    TupleElementSubtype(usize), // tuple[idx] <: type
    PointerSubtype,
    FunctionParamsSubtype,
    FunctionReturnsSubtype,
    FunctionSubtype,

    // Arithmetic Operations (e.g. +, -, *)
    ArithmeticLHS,                 // `lhs + rhs` => type(lhs) <: Int
    ArithmeticRHS,                 // `lhs + rhs` => type(rhs) <: Int
    ArithmeticResult,              // `expr_result = lhs + rhs` => type(expr_result) <: Int
    ArithmeticOp1IntOrOp2Int,      // Operation with either operand being an integer
    ArithmeticOp1Pointer,          // Operation with first operand being a pointer
    ArithmeticOp2Pointer,          // Operation with second operand being a pointer
    ArithmeticResultCharOrInt,     // Arithmetic result is either a char or an integer
    ArithmeticResultOp1IntOp2Int,  // Arithmetic result of int and int
    ArithmeticResultPointerOp1Int, // Arithmetic result of pointer and int
    ArithmeticResultPointerOp2Int, // Arithmetic result of pointer and int
    ArithmeticResultBothInt,
    ArithmeticOperandToIntLikeResult,
    ArithmeticOtherOperandMustBeInt,
    ArithmeticResultMatchesOther,
    ArithmeticIntOperandImpliesResult,

    MemoryAddressCalculation,
    // Memory Operations
    MemoryReadRequiresPointer,
    MemoryWriteRequiresPointer,
    FieldAccess(StructId, usize),

    // Comparison Operations (e.g. <, ==) - often operands are Ints, result is Bool
    ComparisonLHS,    // `lhs < rhs` => type(lhs) <: Int (or other comparable type)
    ComparisonRHS,    // `lhs < rhs` => type(rhs) <: Int (or other comparable type)
    ComparisonResult, // `expr_result = lhs < rhs` => type(expr_result) <: Bool
    EqualityComparisonSameType, // `lhs == rhs` => type(lhs) =:= type(rhs)

    // Unary Operations
    NotOperand,        // `!operand` => type(operand) <: Truthy
    NotResult,         // `expr_result = !operand` => type(expr_result) <: Bool
    UnaryMinusOperand, // `-operand` => type(operand) <: Int
    UnaryMinusResult,  // `expr_result = -operand` => type(expr_result) <: Int

    // Input/Output
    InputSourceType, // `input x` => type(x) <: Char (or chosen input type)
    OutputValueType,
    GlobalVariable(usize),
    SymbolRenaming,
    TupleElement,
}

/// Represents a subtype constraint: `sub_type <: super_type`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Constraint {
    pub sub_type: Type,
    pub super_type: Type,
    pub origin_function_id: FunctionId,
    pub origin_instruction_id: InstructionId,
    pub reason: ConstraintReason,
    pub priority: i32,
}

impl Constraint {
    pub fn new(
        sub_type: Type,
        super_type: Type,
        origin_function_id: FunctionId,
        origin_instruction_id: InstructionId,
        reason: ConstraintReason,
    ) -> Constraint {
        Constraint {
            sub_type,
            super_type,
            origin_function_id,
            origin_instruction_id,
            reason,
            priority: 0,
        }
    }

    pub fn with_priority(&self, priority: i32) -> Constraint {
        let mut c = self.clone();
        c.priority = priority;
        c
    }

    /// Checks if this constraint involves the specified type variable.
    pub fn involves_type_var(&self, tv_id: TypeVarId) -> bool {
        let mut involved_vars = HashSet::new();
        self.sub_type.insert_involved_type_vars(&mut involved_vars);
        self.super_type
            .insert_involved_type_vars(&mut involved_vars);
        involved_vars.contains(&tv_id)
    }

    pub fn display_with<'a, 'b, F>(&'a self, registry: &'b F) -> DisplayableConstraint<'a, 'b, F>
    where
        F: TypeVarRegistry,
    {
        DisplayableConstraint {
            constraint: self,
            _registry: registry,
        }
    }
}

impl fmt::Display for Constraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} <: {}  (from {} at {}, reason: {:?})",
            self.sub_type,
            self.super_type,
            self.origin_function_id,
            self.origin_instruction_id,
            self.reason
        )
    }
}

pub struct DisplayableConstraint<'a, 'b, F>
where
    F: TypeVarRegistry,
{
    constraint: &'a Constraint,
    _registry: &'b F,
}

impl<'a, 'b, F: TypeVarRegistry> fmt::Display for DisplayableConstraint<'a, 'b, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} <: {}  (from {} at {}, reason: {:?})",
            self.constraint.sub_type,
            self.constraint.super_type,
            self.constraint.origin_function_id,
            self.constraint.origin_instruction_id,
            self.constraint.reason
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnclassifiedArithmeticExpression {
    pub function_id: FunctionId,
    pub instruction_id: InstructionId,
    pub expression: Expression<SsaMemoryReference>,
    pub lhs_type: Type,
    pub rhs_type: Type,
    pub result_type: Type,
}

/// A store for collecting and managing type constraints.
/// Ensures that each unique constraint is stored at most once, identified by a ConstraintId.
/// Provides efficient lookup of ConstraintIds involving a specific TypeVarId.
#[derive(Debug, Clone, Default)]
pub struct ConstraintStore {
    /// Stores the actual unique Constraint objects. The index in this Vec acts as the ConstraintId.
    constraints: HashMap<ConstraintId, Constraint>,
    unclassified_add_expressions: Vec<UnclassifiedArithmeticExpression>,
    /// Maps a Constraint (by value) to its unique ConstraintId for quick uniqueness checks.
    constraint_to_id: HashMap<Constraint, ConstraintId>,
    /// Auxiliary index for efficient lookup of ConstraintIds involving a specific TypeVarId.
    type_var_constraints: HashMap<TypeVarId, HashSet<ConstraintId>>,
    parent: HashMap<ConstraintId, ConstraintId>,
}

#[derive(Debug)]
pub enum AddConstraintResult {
    NewConstraint(ConstraintId),
    ExistingConstraint(ConstraintId),
    InvalidConstraint,
}

impl ConstraintStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a new constraint to the store if it's not already present.
    /// BoBool the ConstraintId of the added or existing constraint, and a boolean
    /// indicating if the constraint was newly added (true if new, false if existing).
    /// Internal helper method to add a constraint with specified source
    pub fn add_constraint(
        &mut self,
        constraint: Constraint,
        parent: Option<ConstraintId>,
        state: &InferenceAlgorithmState,
    ) -> AddConstraintResult {
        if let Some(existing_id) = self.constraint_to_id.get(&constraint) {
            return AddConstraintResult::ExistingConstraint(*existing_id);
        }
        if constraint.sub_type == constraint.super_type {
            return AddConstraintResult::InvalidConstraint;
        }

        // Constraint is new
        let new_id_val = self.constraints.len();
        let new_id = ConstraintId(new_id_val);

        self.constraints.insert(new_id, constraint.clone()); // Store the actual constraint
        self.constraint_to_id.insert(constraint.clone(), new_id); // Map constraint value to its ID

        // Update the TypeVar index
        let mut involved_ids = HashSet::new();
        let sub_type = state.resolve_type(&constraint.sub_type);
        let super_type = state.resolve_type(&constraint.super_type);
        sub_type.insert_involved_type_vars(&mut involved_ids);
        super_type.insert_involved_type_vars(&mut involved_ids);

        for tv_id in involved_ids {
            self.type_var_constraints
                .entry(tv_id)
                .or_default()
                .insert(new_id);
        }
        if let Some(parent_id) = parent {
            self.parent.insert(new_id, parent_id);
        }
        AddConstraintResult::NewConstraint(new_id)
    }

    pub fn add_equality_constraint(
        &mut self,
        constraint: Constraint,
        parent: Option<ConstraintId>,
        state: &InferenceAlgorithmState,
    ) {
        let mut reversed = constraint.clone();
        std::mem::swap(&mut reversed.sub_type, &mut reversed.super_type);
        self.add_constraint(constraint, parent, state);
        self.add_constraint(reversed, parent, state);
    }

    pub fn add_unclassified_add_expression(
        &mut self,
        function_id: FunctionId,
        instruction_id: InstructionId,
        expression: Expression<SsaMemoryReference>,
        lhs_type: Type,
        rhs_type: Type,
        result_type: Type,
    ) {
        self.unclassified_add_expressions
            .push(UnclassifiedArithmeticExpression {
                function_id,
                instruction_id,
                expression,
                lhs_type,
                rhs_type,
                result_type,
            });
    }

    /// Gets a reference to a Constraint by its ConstraintId.
    pub fn get_constraint_by_id(&self, id: ConstraintId) -> Option<&Constraint> {
        self.constraints.get(&id)
    }

    /// Gets a reference to the set of ConstraintIds involving a specific TypeVarId.
    pub fn get_constraints_involving_type_var(
        &self,
        tv_id: &TypeVarId,
    ) -> Option<&HashSet<ConstraintId>> {
        self.type_var_constraints.get(tv_id)
    }

    /// Gets the ConstraintId for a given constraint, if it exists in the store.
    pub fn get_constraint_id(&self, constraint: &Constraint) -> Option<ConstraintId> {
        self.constraint_to_id.get(constraint).copied()
    }

    pub fn get_parent_id(&self, constraint_id: ConstraintId) -> Option<ConstraintId> {
        self.parent.get(&constraint_id).copied()
    }

    /// Finds all constraints that originated from a specific instruction.
    pub fn get_constraints_from_instruction(
        &self,
        function_id: FunctionId,
        instruction_id: InstructionId,
    ) -> Vec<&Constraint> {
        self.constraints
            .iter()
            .filter(|(_, constraint)| {
                constraint.origin_function_id == function_id
                    && constraint.origin_instruction_id == instruction_id
            })
            .map(|(_, constraint)| constraint)
            .collect()
    }

    /// Finds all constraint IDs that originated from a specific instruction.
    pub fn get_constraint_ids_from_instruction(
        &self,
        function_id: FunctionId,
        instruction_id: InstructionId,
    ) -> Vec<ConstraintId> {
        self.constraints
            .iter()
            .enumerate()
            .filter_map(|(idx, (_, constraint))| {
                if constraint.origin_function_id == function_id
                    && constraint.origin_instruction_id == instruction_id
                {
                    Some(ConstraintId(idx))
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn iter_unclassified_add_expressions(
        &self,
    ) -> impl Iterator<Item = &UnclassifiedArithmeticExpression> {
        self.unclassified_add_expressions.iter()
    }

    /// Provides an iterator over all unique constraints (as &Constraint) in the store.
    /// Returns constraints in deterministic order sorted by ConstraintId.
    pub fn iter(&self) -> impl Iterator<Item = (&ConstraintId, &Constraint)> {
        let mut items: Vec<_> = self.constraints.iter().collect();
        items.sort_by_key(|(id, _)| id.index());
        items.into_iter()
    }

    /// Gets the total number of unique constraints in the store.
    pub fn len(&self) -> usize {
        self.constraints.len()
    }

    /// Returns true if the store contains no unique constraints.
    pub fn is_empty(&self) -> bool {
        self.constraints.is_empty()
    }

    pub fn update_constraints_involving_type_var_id(
        &mut self,
        tv_id: TypeVarId,
        state: &InferenceAlgorithmState,
    ) {
        let constraint_ids = self
            .get_constraints_involving_type_var(&tv_id)
            .into_iter()
            .flatten()
            .copied()
            .collect_vec();
        for c_id in constraint_ids {
            let c = self.constraints.get_mut(&c_id).unwrap();
            let new_sub_type = state.resolve_type(&c.sub_type);
            let new_super_type = state.resolve_type(&c.super_type);
            let mut involved_types = HashSet::new();
            new_sub_type.insert_involved_type_vars(&mut involved_types);
            new_super_type.insert_involved_type_vars(&mut involved_types);
            for t in involved_types {
                self.type_var_constraints.entry(t).or_default().insert(c_id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::v3::{FunctionId, InstructionId};
    // Ensure Type and its variants needed for tests are correctly imported
    use super::super::types::Type::{self, Any, Bool, Int};

    fn make_test_constraint(sub: Type, sup: Type, reason: ConstraintReason) -> Constraint {
        Constraint::new(sub, sup, FunctionId::new(0), InstructionId::new(0), reason)
    }

    #[test]
    fn test_add_constraint_uniqueness_and_id() {
        let mut store = ConstraintStore::new();
        let state = InferenceAlgorithmState::new();

        let c1_val = make_test_constraint(Int, Any, ConstraintReason::Assignment);
        let c2_val = make_test_constraint(Int, Any, ConstraintReason::Assignment); // Identical to c1
        let c3_val = make_test_constraint(Bool, Int, ConstraintReason::Assignment);

        let id1 = match store.add_constraint(c1_val.clone(), None, &state) {
            AddConstraintResult::NewConstraint(id) => id,
            _ => panic!("Adding c1 should succeed"),
        };
        assert_eq!(store.len(), 1);

        let id2 = match store.add_constraint(c2_val.clone(), None, &state) {
            AddConstraintResult::ExistingConstraint(id) => id,
            _ => panic!("Adding c2 (duplicate) should not report as new"),
        };
        assert_eq!(id1, id2, "IDs for identical constraints should be the same");
        assert_eq!(store.len(), 1);

        let id3 = match store.add_constraint(c3_val.clone(), None, &state) {
            AddConstraintResult::NewConstraint(id) => id,
            _ => panic!("Adding c3 should succeed"),
        };
        assert_ne!(id1, id3, "ID for c3 should be different from c1");
        assert_eq!(store.len(), 2);

        assert_eq!(store.get_constraint_by_id(id1), Some(&c1_val));
        assert_eq!(store.get_constraint_by_id(id3), Some(&c3_val));
    }

    #[test]
    fn test_iteration_and_len_with_ids() {
        let mut store = ConstraintStore::new();
        let state = InferenceAlgorithmState::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);

        let c1 = make_test_constraint(Int, Any, ConstraintReason::Assignment);
        let c2 = make_test_constraint(Bool, Int, ConstraintReason::Assignment);

        let id1 = match store.add_constraint(c1.clone(), None, &state) {
            AddConstraintResult::NewConstraint(id) => id,
            AddConstraintResult::ExistingConstraint(id) => id,
            AddConstraintResult::InvalidConstraint => panic!("Unexpected invalid constraint"),
        };
        assert!(!store.is_empty());
        assert_eq!(store.len(), 1);

        let id2 = match store.add_constraint(c2.clone(), None, &state) {
            AddConstraintResult::NewConstraint(id) => id,
            AddConstraintResult::ExistingConstraint(id) => id,
            AddConstraintResult::InvalidConstraint => panic!("Unexpected invalid constraint"),
        };
        assert_eq!(store.len(), 2);

        // Add duplicate of c1
        let id1_dup = match store.add_constraint(c1.clone(), None, &state) {
            AddConstraintResult::NewConstraint(_) => panic!("Unexpected new constraint"),
            AddConstraintResult::ExistingConstraint(id) => id,
            AddConstraintResult::InvalidConstraint => panic!("Unexpected invalid constraint"),
        };
        assert_eq!(id1_dup, id1);
        assert_eq!(store.len(), 2); // Length should not change

        let mut count = 0;
        let mut found_c1 = false;
        let mut found_c2 = false;
        for constraint_ref in store.iter() {
            count += 1;
            if *constraint_ref.0 == id1 {
                found_c1 = true;
            }
            if *constraint_ref.0 == id2 {
                found_c2 = true;
            }
        }
        assert_eq!(count, 2);
        assert!(found_c1);
        assert!(found_c2);

        let mut id_count = 0;
        let mut found_id1 = false;
        let mut found_id2 = false;
        let mut ids_from_iter = HashSet::new();
        for (id_val, _) in store.iter() {
            id_count += 1;
            ids_from_iter.insert(*id_val);
            if *id_val == id1 {
                found_id1 = true;
            }
            if *id_val == id2 {
                found_id2 = true;
            }
        }
        assert_eq!(id_count, 2);
        assert!(found_id1);
        assert!(found_id2);
        assert_eq!(ids_from_iter.len(), 2, "iter_ids should produce unique ids");
    }

    #[test]
    fn test_constraint_lookup_methods() {
        let mut store = ConstraintStore::new();
        let state = InferenceAlgorithmState::new();

        let c1 = make_test_constraint(Int, Any, ConstraintReason::Assignment);
        let id1 = match store.add_constraint(c1.clone(), None, &state) {
            AddConstraintResult::NewConstraint(id) => id,
            AddConstraintResult::ExistingConstraint(id) => id,
            AddConstraintResult::InvalidConstraint => panic!("Unexpected invalid constraint"),
        };

        // Test reverse lookup
        assert_eq!(store.get_constraint_id(&c1), Some(id1));

        // Test instruction-based lookup
        let constraints_from_inst =
            store.get_constraints_from_instruction(FunctionId::new(0), InstructionId::new(0));
        assert_eq!(constraints_from_inst.len(), 1);
        assert_eq!(*constraints_from_inst[0], c1);

        let constraint_ids_from_inst =
            store.get_constraint_ids_from_instruction(FunctionId::new(0), InstructionId::new(0));
        assert_eq!(constraint_ids_from_inst.len(), 1);
        assert_eq!(constraint_ids_from_inst[0], id1);
    }
}
