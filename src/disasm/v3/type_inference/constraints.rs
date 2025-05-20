// disasm/src/disasm/v3/type_inference/constraints.rs

use log::trace;

use super::{
    types::{Type, TypeVarId},
    InferenceAlgorithmState,
};

use crate::disasm::v3::{
    lir::Expression, ssa::SsaMemoryReference, type_inference::type_bounds_map::TypeVarRegistry,
    FunctionId, InstructionId,
};
use std::{
    collections::{HashMap, HashSet},
    fmt,
}; // Assuming types.rs is in the parent module (type_inference)

/// A unique identifier for a constraint within a ConstraintStore.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConstraintId(usize);

/// Describes the reason a type constraint was generated.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConstraintReason {
    // General
    Assignment,               // target = src  => type(src) <: type(target)
    TypeVariableSubstitution, // TypeVar(X) used where TypeVar(Y) is expected, etc.
    PhiNodeOperand,           // Incoming value to a PHI node: type(incoming) <: type(phi_dest)

    // Literals
    LiteralInteger, // A literal number implies Int type, e.g. `5` => TypeVar(N) <: Int
    LiteralBoolean, // A literal boolean (true/false, or 0/1 if distinguished) => TypeVar(N) <: Bool
    // LiteralTruthy might be derived via Bool <: Truthy, so not strictly needed here.

    // Control Flow
    IfConditionOperand, // `if cond ...` => type(cond) <: Truthy

    // Function Calls & Returns
    FunctionCallImpliesFunctionType, // `f(...)` => type(f) <: Function { params: FreshTV, returns: FreshTV }
    FunctionCallArgument(usize /* argument index */), // type(actual_arg_i) <: type(formal_param_i)
    ReturnStatement,                 // `return expr;` => type(expr) <: function_return_type

    // Pointer Operations
    DereferenceRequiresPointer, // `*ptr_expr` (read context) => type(ptr_expr) <: Pointer(FreshTV for pointee)
    AssignmentToDereferenceTarget, // `*ptr_expr = src` => type(ptr_expr) <: Pointer(type(src))

    // Arithmetic Operations (e.g. +, -, *)
    ArithmeticLHS,    // `lhs + rhs` => type(lhs) <: Int
    ArithmeticRHS,    // `lhs + rhs` => type(rhs) <: Int
    ArithmeticResult, // `expr_result = lhs + rhs` => type(expr_result) <: Int

    // Comparison Operations (e.g. <, ==) - often operands are Ints, result is Bool
    ComparisonLHS,    // `lhs < rhs` => type(lhs) <: Int (or other comparable type)
    ComparisonRHS,    // `lhs < rhs` => type(rhs) <: Int (or other comparable type)
    ComparisonResult, // `expr_result = lhs < rhs` => type(expr_result) <: Bool

    // Unary Operations
    NotOperand,        // `!operand` => type(operand) <: Truthy
    NotResult,         // `expr_result = !operand` => type(expr_result) <: Bool
    UnaryMinusOperand, // `-operand` => type(operand) <: Int
    UnaryMinusResult,  // `expr_result = -operand` => type(expr_result) <: Int

    // Input/Output
    InputSourceType, // `input x` => type(x) <: Char (or chosen input type)
    OutputValueType, // `output x` => type(x) <: Int (or Char, if outputting characters)
}

/// Represents a subtype constraint: `sub_type <: super_type`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Constraint {
    pub sub_type: Type,
    pub super_type: Type,
    pub origin_function_id: FunctionId,
    pub origin_instruction_id: InstructionId,
    pub reason: ConstraintReason,
}

impl Constraint {
    pub fn new(
        sub_type: Type,
        super_type: Type,
        origin_function_id: FunctionId,
        origin_instruction_id: InstructionId,
        reason: ConstraintReason,
    ) -> Self {
        Constraint {
            sub_type,
            super_type,
            origin_function_id,
            origin_instruction_id,
            reason,
        }
    }

    pub fn display_with<'a, 'b, F>(&'a self, registry: &'b F) -> DisplayableConstraint<'a, 'b, F>
    where
        F: TypeVarRegistry,
    {
        DisplayableConstraint {
            constraint: self,
            registry,
        }
    }
}

pub struct DisplayableConstraint<'a, 'b, F>
where
    F: TypeVarRegistry,
{
    constraint: &'a Constraint,
    registry: &'b F,
}

impl<'a, 'b, F: TypeVarRegistry> fmt::Display for DisplayableConstraint<'a, 'b, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} <: {}  (from {} at {}, reason: {:?})",
            self.constraint.sub_type.display_with(self.registry),
            self.constraint.super_type.display_with(self.registry),
            self.constraint.origin_function_id,
            self.constraint.origin_instruction_id,
            self.constraint.reason
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct UnclasifiedArithmeticExpresction {
    expression: Expression<SsaMemoryReference>,
    lhs_type: Type,
    rhs_type: Type,
    result_type: Type,
}

/// A store for collecting and managing type constraints.
/// Ensures that each unique constraint is stored at most once, identified by a ConstraintId.
/// Provides efficient lookup of ConstraintIds involving a specific TypeVarId.
#[derive(Debug, Clone)]
pub struct ConstraintStore {
    /// Stores the actual unique Constraint objects. The index in this Vec acts as the ConstraintId.
    constraints: Vec<Constraint>,
    unclassified_add_expressions: Vec<UnclasifiedArithmeticExpresction>,
    /// Maps a Constraint (by value) to its unique ConstraintId for quick uniqueness checks.
    constraint_to_id: HashMap<Constraint, ConstraintId>,
    /// Auxiliary index for efficient lookup of ConstraintIds involving a specific TypeVarId.
    type_var_constraints: HashMap<TypeVarId, HashSet<ConstraintId>>,
}

impl ConstraintStore {
    pub fn new() -> Self {
        ConstraintStore {
            constraints: Vec::new(),
            unclassified_add_expressions: Vec::new(),
            constraint_to_id: HashMap::new(),
            type_var_constraints: HashMap::new(),
        }
    }

    /// Adds a new constraint to the store if it's not already present.
    /// Returns the ConstraintId of the added or existing constraint, and a boolean
    /// indicating if the constraint was newly added (true if new, false if existing).
    pub fn add_constraint(
        &mut self,
        constraint: Constraint,
        state: &InferenceAlgorithmState,
    ) -> (ConstraintId, bool) {
        if let Some(existing_id) = self.constraint_to_id.get(&constraint) {
            return (*existing_id, false); // Constraint already exists
        }

        // Constraint is new
        let new_id_val = self.constraints.len();
        let new_id = ConstraintId(new_id_val);

        self.constraints.push(constraint.clone()); // Store the actual constraint
        self.constraint_to_id.insert(constraint.clone(), new_id); // Map constraint value to its ID

        // Update the TypeVar index
        let mut involved_ids = HashSet::new();
        constraint
            .sub_type
            .collect_involved_type_vars(&mut involved_ids);
        constraint
            .super_type
            .collect_involved_type_vars(&mut involved_ids);

        for tv_id in involved_ids {
            self.type_var_constraints
                .entry(tv_id)
                .or_default()
                .insert(new_id);
        }
        trace!("Added constraint {}", constraint.display_with(state));
        (new_id, true)
    }

    pub fn add_equality_constraint(
        &mut self,
        constraint: Constraint,
        state: &InferenceAlgorithmState,
    ) -> bool {
        let mut reversed = constraint.clone();
        std::mem::swap(&mut reversed.sub_type, &mut reversed.super_type);
        let add1 = self.add_constraint(constraint, state).1;
        let add2 = self.add_constraint(reversed, state).1;
        add1 || add2
    }

    pub fn add_unclassified_add_expression(
        &mut self,
        expression: Expression<SsaMemoryReference>,
        lhs_type: Type,
        rhs_type: Type,
        result_type: Type,
    ) {
        self.unclassified_add_expressions
            .push(UnclasifiedArithmeticExpresction {
                expression,
                lhs_type,
                rhs_type,
                result_type,
            });
    }

    /// Gets a reference to a Constraint by its ConstraintId.
    pub fn get_constraint_by_id(&self, id: ConstraintId) -> Option<&Constraint> {
        self.constraints.get(id.0)
    }

    /// Gets a reference to the set of ConstraintIds involving a specific TypeVarId.
    pub fn get_constraints_involving_type_var(
        &self,
        tv_id: &TypeVarId,
    ) -> Option<&HashSet<ConstraintId>> {
        self.type_var_constraints.get(tv_id)
    }

    pub fn iter_unclassified_add_expressions(
        &self,
    ) -> impl Iterator<Item = &UnclasifiedArithmeticExpresction> {
        self.unclassified_add_expressions.iter()
    }

    pub fn remove_unclassified_add_expressions(
        &mut self,
        expression: &UnclasifiedArithmeticExpresction,
    ) {
        self.unclassified_add_expressions
            .retain(|e| e != expression);
    }

    /// Provides an iterator over all unique constraints (as &Constraint) in the store.
    pub fn iter(&self) -> impl Iterator<Item = &Constraint> {
        self.constraints.iter()
    }

    /// Provides an iterator over all unique ConstraintIds in the store.
    pub fn iter_ids(&self) -> impl Iterator<Item = ConstraintId> + '_ {
        (0..self.constraints.len()).map(ConstraintId)
    }

    /// Gets the total number of unique constraints in the store.
    pub fn len(&self) -> usize {
        self.constraints.len()
    }

    /// Returns true if the store contains no unique constraints.
    pub fn is_empty(&self) -> bool {
        self.constraints.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::v3::{FunctionId, InstructionId};
    // Ensure Type and its variants needed for tests are correctly imported
    use super::super::types::Type::{
        self, Any, Bool, Function, Int, Pointer, Tuple, TypeVar, GLB, LUB,
    };

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

        let (id1, added1) = store.add_constraint(c1_val.clone(), &state);
        assert!(added1, "Adding c1 should succeed");
        assert_eq!(store.len(), 1);

        let (id2, added2) = store.add_constraint(c2_val.clone(), &state);
        assert!(!added2, "Adding c2 (duplicate) should not report as new");
        assert_eq!(id1, id2, "IDs for identical constraints should be the same");
        assert_eq!(store.len(), 1);

        let (id3, added3) = store.add_constraint(c3_val.clone(), &state);
        assert!(added3, "Adding c3 should succeed");
        assert_ne!(id1, id3, "ID for c3 should be different from c1");
        assert_eq!(store.len(), 2);

        assert_eq!(store.get_constraint_by_id(id1), Some(&c1_val));
        assert_eq!(store.get_constraint_by_id(id3), Some(&c3_val));
    }

    #[test]
    fn test_get_constraints_involving_type_var_with_ids() {
        let mut store = ConstraintStore::new();
        let state = InferenceAlgorithmState::new();

        let tv1_id_val: TypeVarId = TypeVarId::new(1);
        let tv2_id_val: TypeVarId = TypeVarId::new(2);
        let tv3_id_val: TypeVarId = TypeVarId::new(3);
        let tv4_id_val: TypeVarId = TypeVarId::new(4);

        let tv1 = TypeVar(tv1_id_val);
        let tv2 = TypeVar(tv2_id_val);
        let tv3 = TypeVar(tv3_id_val);
        let tv4 = TypeVar(tv4_id_val);

        // Constraints
        let c_tv1_int = make_test_constraint(tv1.clone(), Int, ConstraintReason::Assignment);
        let c_bool_tv1 = make_test_constraint(Bool, tv1.clone(), ConstraintReason::Assignment);
        let c_tv2_tv1 =
            make_test_constraint(tv2.clone(), tv1.clone(), ConstraintReason::Assignment);
        let c_tv2_tv3 =
            make_test_constraint(tv2.clone(), tv3.clone(), ConstraintReason::Assignment);
        let c_no_tv = make_test_constraint(Int, Any, ConstraintReason::Assignment);
        let c_ptr_tv1_ptr_tv2 = make_test_constraint(
            Pointer(Box::new(tv1.clone())),
            Pointer(Box::new(tv2.clone())),
            ConstraintReason::Assignment,
        );
        let c_tuple_tv3_int_tuple_tv4_any = make_test_constraint(
            Tuple(vec![tv3.clone(), Int]),
            Tuple(vec![tv4.clone(), Any]),
            ConstraintReason::Assignment,
        );
        let c_func_tv1_tv2_func_tv3_tv4 = make_test_constraint(
            Function {
                params: Box::new(Tuple(vec![tv1.clone()])),
                returns: Box::new(Pointer(Box::new(tv2.clone()))),
            },
            Function {
                params: Box::new(Tuple(vec![tv3.clone()])),
                returns: Box::new(Pointer(Box::new(tv4.clone()))),
            },
            ConstraintReason::FunctionCallImpliesFunctionType,
        );
        let c_glb_tv1_int_tv2 = make_test_constraint(
            GLB(Box::new(tv1.clone()), Box::new(Int)),
            tv2.clone(),
            ConstraintReason::TypeVariableSubstitution,
        );
        let c_tv3_lub_tv4_bool = make_test_constraint(
            tv3.clone(),
            LUB(Box::new(tv4.clone()), Box::new(Bool)),
            ConstraintReason::TypeVariableSubstitution,
        );

        // Add constraints and get their IDs
        let (id_c_tv1_int, _) = store.add_constraint(c_tv1_int.clone(), &state);
        let (id_c_bool_tv1, _) = store.add_constraint(c_bool_tv1.clone(), &state);
        let (id_c_tv2_tv1, _) = store.add_constraint(c_tv2_tv1.clone(), &state);
        let (id_c_tv2_tv3, _) = store.add_constraint(c_tv2_tv3.clone(), &state);
        store.add_constraint(c_no_tv.clone(), &state); // ID not explicitly tracked for this test
        let (id_c_ptr_tv1_ptr_tv2, _) = store.add_constraint(c_ptr_tv1_ptr_tv2.clone(), &state);
        let (id_c_tuple_tv3_int_tuple_tv4_any, _) =
            store.add_constraint(c_tuple_tv3_int_tuple_tv4_any.clone(), &state);
        let (id_c_func_tv1_tv2_func_tv3_tv4, _) =
            store.add_constraint(c_func_tv1_tv2_func_tv3_tv4.clone(), &state);
        let (id_c_glb_tv1_int_tv2, _) = store.add_constraint(c_glb_tv1_int_tv2.clone(), &state);
        let (id_c_tv3_lub_tv4_bool, _) = store.add_constraint(c_tv3_lub_tv4_bool.clone(), &state);

        assert_eq!(store.len(), 10);

        // Check tv1_id_val
        let constr_ids_tv1 = store
            .get_constraints_involving_type_var(&tv1_id_val)
            .expect("Should find constraint IDs for tv1");
        assert_eq!(constr_ids_tv1.len(), 6, "tv1 involved count mismatch");
        assert!(constr_ids_tv1.contains(&id_c_tv1_int));
        assert!(constr_ids_tv1.contains(&id_c_bool_tv1));
        assert!(constr_ids_tv1.contains(&id_c_tv2_tv1));
        assert!(constr_ids_tv1.contains(&id_c_ptr_tv1_ptr_tv2));
        assert!(constr_ids_tv1.contains(&id_c_func_tv1_tv2_func_tv3_tv4));
        assert!(constr_ids_tv1.contains(&id_c_glb_tv1_int_tv2));

        // Check tv2_id_val
        let constr_ids_tv2 = store
            .get_constraints_involving_type_var(&tv2_id_val)
            .expect("Should find constraint IDs for tv2");
        assert_eq!(constr_ids_tv2.len(), 5, "tv2 involved count mismatch");
        assert!(constr_ids_tv2.contains(&id_c_tv2_tv1));
        assert!(constr_ids_tv2.contains(&id_c_tv2_tv3));
        assert!(constr_ids_tv2.contains(&id_c_ptr_tv1_ptr_tv2));
        assert!(constr_ids_tv2.contains(&id_c_func_tv1_tv2_func_tv3_tv4));
        assert!(constr_ids_tv2.contains(&id_c_glb_tv1_int_tv2));

        // Check tv3_id_val
        let constr_ids_tv3 = store
            .get_constraints_involving_type_var(&tv3_id_val)
            .expect("Should find constraint IDs for tv3");
        assert_eq!(constr_ids_tv3.len(), 4, "tv3 involved count mismatch");
        assert!(constr_ids_tv3.contains(&id_c_tv2_tv3));
        assert!(constr_ids_tv3.contains(&id_c_tuple_tv3_int_tuple_tv4_any));
        assert!(constr_ids_tv3.contains(&id_c_func_tv1_tv2_func_tv3_tv4));
        assert!(constr_ids_tv3.contains(&id_c_tv3_lub_tv4_bool));

        // Check tv4_id_val
        let constr_ids_tv4 = store
            .get_constraints_involving_type_var(&tv4_id_val)
            .expect("Should find constraint IDs for tv4");
        assert_eq!(constr_ids_tv4.len(), 3, "tv4 involved count mismatch");
        assert!(constr_ids_tv4.contains(&id_c_tuple_tv3_int_tuple_tv4_any));
        assert!(constr_ids_tv4.contains(&id_c_func_tv1_tv2_func_tv3_tv4));
        assert!(constr_ids_tv4.contains(&id_c_tv3_lub_tv4_bool));

        // Check a TypeVarId not in any constraint
        assert!(store
            .get_constraints_involving_type_var(&TypeVarId::new(99))
            .is_none());
    }

    #[test]
    fn test_iteration_and_len_with_ids() {
        let mut store = ConstraintStore::new();
        let state = InferenceAlgorithmState::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);

        let c1 = make_test_constraint(Int, Any, ConstraintReason::Assignment);
        let c2 = make_test_constraint(Bool, Int, ConstraintReason::Assignment);

        let (id1, _) = store.add_constraint(c1.clone(), &state);
        assert!(!store.is_empty());
        assert_eq!(store.len(), 1);

        let (id2, _) = store.add_constraint(c2.clone(), &state);
        assert_eq!(store.len(), 2);

        // Add duplicate of c1
        let (id1_dup, added_dup) = store.add_constraint(c1.clone(), &state);
        assert!(!added_dup);
        assert_eq!(id1_dup, id1);
        assert_eq!(store.len(), 2); // Length should not change

        let mut count = 0;
        let mut found_c1 = false;
        let mut found_c2 = false;
        for constraint_ref in store.iter() {
            count += 1;
            if *constraint_ref == c1 {
                found_c1 = true;
            }
            if *constraint_ref == c2 {
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
        for id_val in store.iter_ids() {
            id_count += 1;
            ids_from_iter.insert(id_val);
            if id_val == id1 {
                found_id1 = true;
            }
            if id_val == id2 {
                found_id2 = true;
            }
        }
        assert_eq!(id_count, 2);
        assert!(found_id1);
        assert!(found_id2);
        assert_eq!(ids_from_iter.len(), 2, "iter_ids should produce unique ids");
    }
}
