use std::{collections::HashMap, fmt};

use itertools::Itertools;

use super::{
    control_flow_graph::{Block, BlockId, NextKind},
    low_ir::{Arg, ArgBase, GenericInstruction},
    program_analysis::ProgramAnalysis,
    ssa_form::{convert_to_ssa, SSAArg},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SSAArgIdentity {
    arg: Arg,
    version: usize,
    deref_version: usize,
}

impl fmt::Display for SSAArgIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.arg {
            Arg::Value(x) => write!(f, "{}", x), // No version for immediate values
            Arg::Deref(addr) => write!(f, "[[{}]_{}]", addr, self.deref_version),
            _ => write!(f, "{}_{}", self.arg, self.version),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Var {
    block_id: BlockId,
    ssa_arg: SSAArgIdentity,
}

impl Var {
    pub fn new(block_id: BlockId, ssa_arg: SSAArg) -> Var {
        Var {
            block_id,
            ssa_arg: SSAArgIdentity {
                arg: ssa_arg.arg,
                version: ssa_arg.version,
                deref_version: ssa_arg.deref_version,
            },
        }
    }
}

impl fmt::Display for Var {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}:{}", self.block_id, self.ssa_arg)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TypeVarId(usize);

impl fmt::Display for TypeVarId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "t{}", self.0)
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub enum Type {
    Int,
    Bool,
    Char,
    Pointer(Box<Type>),
    FunctionPointer { args: Vec<Type>, returns: Vec<Type> },
    String,
    TypeVar(TypeVarId),
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::Int => write!(f, "int"),
            Type::Bool => write!(f, "bool"),
            Type::Char => write!(f, "char"),
            Type::Pointer(t) => write!(f, "*{}", t),
            Type::FunctionPointer { args, returns } => {
                write!(f, "fn(")?;
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", arg)?;
                }
                write!(f, ") -> ")?;
                for (i, ret) in returns.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", ret)?;
                }
                if returns.is_empty() {
                    write!(f, "void")?;
                }
                Ok(())
            }
            Type::String => write!(f, "string"),
            Type::TypeVar(t @ TypeVarId(_)) => write!(f, "{}", t),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ConstraintReason {
    AddImpliesInt,
    MulImpliesInt,
    CompareDstImpliesBool,
    CompareSrcImpliesInt,
    OutputImpliesChar,
    InputImpliesChar,
    JumpConditionImpliesBool,
    CompareSrcSameType,
    Assignment,
    Deref,
    FunctionParameterBinding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Constraint {
    left: Type,
    right: Type,
    addr: usize,
    reason: ConstraintReason,
}

impl fmt::Display for Constraint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Constraint: {} = {} at {} because {:?}",
            self.left, self.right, self.addr, self.reason
        )
    }
}

pub struct TypeInference {
    constraints: Vec<Constraint>,
    type_vars: HashMap<Var, Type>,
    debug_markers: HashMap<char, Var>,
}

impl TypeInference {
    pub fn new() -> Self {
        Self {
            constraints: Vec::new(),
            type_vars: HashMap::new(),
            debug_markers: HashMap::new(),
        }
    }

    fn fresh_type_var(&self) -> Type {
        Type::TypeVar(TypeVarId(self.type_vars.len() + 1))
    }

    pub fn type_for_ssa_arg(&mut self, block_id: BlockId, ssa_arg: SSAArg) -> Type {
        self.type_for_arg(Var::new(block_id, ssa_arg), ssa_arg.debug_marker)
    }

    pub fn type_for_arg(&mut self, var: Var, debug_marker: Option<char>) -> Type {
        if let Some(debug_marker) = debug_marker {
            self.debug_markers.insert(debug_marker, var);
        }
        if let Some(typ) = self.type_vars.get(&var).cloned() {
            return typ;
        }
        /*
        match var.ssa_arg.arg {
            super::low_ir::Arg::Mem(_) => todo!(),
            super::low_ir::Arg::Value(_) => todo!(),
            super::low_ir::Arg::RelativeMem(_) => todo!(),
            super::low_ir::Arg::Deref(usize) => todo!(),
        }
        */
        let typ = self.fresh_type_var();
        self.type_vars.insert(var, typ.clone());
        if let Arg::Deref(addr) = var.ssa_arg.arg {
            let inner_var = SSAArg {
                arg: Arg::Mem(addr as i128),
                version: var.ssa_arg.deref_version,
                deref_version: 0,
                debug_marker: None,
            };
            let pointer = self.type_for_arg(Var::new(var.block_id, inner_var), None);
            self.add_constraint(
                pointer,
                Type::Pointer(Box::new(typ.clone())),
                addr,
                ConstraintReason::Deref,
            );
        }
        typ
    }

    fn add_constraint(&mut self, left: Type, right: Type, addr: usize, reason: ConstraintReason) {
        println!("Adding constraint: {:?} = {:?} ({:?})", left, right, reason);
        self.constraints.push(Constraint {
            left,
            right,
            addr,
            reason,
        });
    }

    fn generate_constraint_for_op(
        &mut self,
        block_id: BlockId,
        addr: usize,
        op: &GenericInstruction<SSAArg>,
    ) {
        match op {
            GenericInstruction::Assign(src, dst) => {
                let dst_type = self.type_for_ssa_arg(block_id, *dst);
                let src_type = self.type_for_ssa_arg(block_id, *src);
                self.add_constraint(src_type, dst_type, addr, ConstraintReason::Assignment);
            }
            GenericInstruction::Add(src1, src2, dst) => {
                let dst_type = self.type_for_ssa_arg(block_id, *dst);
                let src1_type = self.type_for_ssa_arg(block_id, *src1);
                let src2_type = self.type_for_ssa_arg(block_id, *src2);
                self.add_constraint(dst_type, Type::Int, addr, ConstraintReason::AddImpliesInt);
                self.add_constraint(src1_type, Type::Int, addr, ConstraintReason::AddImpliesInt);
                self.add_constraint(src2_type, Type::Int, addr, ConstraintReason::AddImpliesInt);
            }
            GenericInstruction::Mul(src1, src2, dst) => {
                let dst_type = self.type_for_ssa_arg(block_id, *dst);
                let src1_type = self.type_for_ssa_arg(block_id, *src1);
                let src2_type = self.type_for_ssa_arg(block_id, *src2);
                self.add_constraint(dst_type, Type::Int, addr, ConstraintReason::MulImpliesInt);
                self.add_constraint(src1_type, Type::Int, addr, ConstraintReason::MulImpliesInt);
                self.add_constraint(src2_type, Type::Int, addr, ConstraintReason::MulImpliesInt);
            }
            GenericInstruction::LessThan(src1, src2, dst) => {
                let dst_type = self.type_for_ssa_arg(block_id, *dst);
                let src1_type = self.type_for_ssa_arg(block_id, *src1);
                let src2_type = self.type_for_ssa_arg(block_id, *src2);
                self.add_constraint(
                    dst_type,
                    Type::Bool,
                    addr,
                    ConstraintReason::CompareDstImpliesBool,
                );
                self.add_constraint(
                    src1_type,
                    Type::Int,
                    addr,
                    ConstraintReason::CompareSrcImpliesInt,
                );
                self.add_constraint(
                    src2_type,
                    Type::Int,
                    addr,
                    ConstraintReason::CompareSrcImpliesInt,
                );
            }
            GenericInstruction::Equals(src1, src2, dest) => {
                let dst_type = self.type_for_ssa_arg(block_id, *dest);
                let src1_type = self.type_for_ssa_arg(block_id, *src1);
                let src2_type = self.type_for_ssa_arg(block_id, *src2);
                self.add_constraint(
                    dst_type,
                    Type::Bool,
                    addr,
                    ConstraintReason::CompareDstImpliesBool,
                );
                self.add_constraint(
                    src1_type,
                    src2_type,
                    addr,
                    ConstraintReason::CompareSrcSameType,
                );
            }
            GenericInstruction::Output(src) => {
                let src_type = self.type_for_ssa_arg(block_id, *src);
                self.add_constraint(
                    src_type,
                    Type::Char,
                    addr,
                    ConstraintReason::OutputImpliesChar,
                );
            }
            GenericInstruction::Input(dst) => {
                let dst_type = self.type_for_ssa_arg(block_id, *dst);
                self.add_constraint(
                    dst_type,
                    Type::Char,
                    addr,
                    ConstraintReason::InputImpliesChar,
                );
            }
            GenericInstruction::JumpIf(src, ..) => {
                let src_type = self.type_for_ssa_arg(block_id, *src);
                self.add_constraint(
                    src_type,
                    Type::Bool,
                    addr,
                    ConstraintReason::JumpConditionImpliesBool,
                );
            }
            GenericInstruction::Phi(dst, srcs) => {
                let dst_type = self.type_for_ssa_arg(block_id, *dst);
                for i in srcs {
                    if dst == i {
                        continue;
                    }
                    let s = self.type_for_ssa_arg(block_id, *i);
                    self.add_constraint(dst_type.clone(), s, addr, ConstraintReason::Assignment);
                }
            }
            _ => {}
        }
    }

    fn generate_constraint_for_block(
        &mut self,
        program: &ProgramAnalysis,
        scope: BlockId,
        block: &Block<SSAArg>,
    ) {
        for (addr, op) in &block.ops {
            self.generate_constraint_for_op(scope, *addr, op);
        }
        if let NextKind::FunctionCall(call) = &block.next {
            let fcall = self.type_for_arg(Var::new(scope, call.function_addr), None);
            self.add_constraint(
                fcall,
                Type::FunctionPointer {
                    args: vec![],
                    returns: vec![],
                },
                block.span.end,
                ConstraintReason::Assignment,
            );
            if let Some(addr) = call.function_addr.value() {
                if let Some(fun) = program.function_infos.get(&(addr as usize).into()) {
                    for arg in call.arguments.as_ref().unwrap() {
                        let rvalue = arg.as_arg().relative_mem().unwrap();
                        let left = self.type_for_ssa_arg(block.id(), *arg);
                        let rarg = Arg::RelativeMem(rvalue - (fun.stack_size as i128));
                        let right = self.type_for_ssa_arg(
                            fun.start_block,
                            SSAArg {
                                arg: Arg::RelativeMem(rvalue - (fun.stack_size as i128)),
                                version: 0,
                                deref_version: 0,
                                debug_marker: None,
                            },
                        );
                        println!("* larg: {:?} {}", arg, rarg);
                        self.add_constraint(
                            left,
                            right,
                            block.span.end,
                            ConstraintReason::FunctionParameterBinding,
                        );
                    }
                }
            }
        }
    }

    pub fn generate_constaints_for_program(&mut self, program: &ProgramAnalysis) {
        for cfg in program.control_flows.values().sorted_by_key(|c| c.start) {
            let data_flow = &program.data_flows[&cfg.start];
            let ssa_graph = convert_to_ssa(program, &cfg, &data_flow);
            for block in ssa_graph.blocks.values().sorted_by_key(|b| b.span.start) {
                self.generate_constraint_for_block(program, cfg.start, block);
            }
        }
    }

    pub fn substitute(t: Type, subst: &HashMap<TypeVarId, Type>) -> Type {
        match t {
            Type::Int => Type::Int,
            Type::Bool => Type::Bool,
            Type::Char => Type::Char,
            Type::Pointer(t) => Type::Pointer(Box::new(Self::substitute(*t, subst))),
            Type::FunctionPointer { args, returns } => Type::FunctionPointer {
                args: args
                    .into_iter()
                    .map(|t| Self::substitute(t, subst))
                    .collect(),
                returns: returns
                    .into_iter()
                    .map(|t| Self::substitute(t, subst))
                    .collect(),
            },
            Type::String => Type::String,
            Type::TypeVar(id) => subst.get(&id).cloned().unwrap_or(Type::TypeVar(id)),
        }
    }

    pub fn unify(&self) -> Result<HashMap<TypeVarId, Type>, String> {
        let mut worklist = self.constraints.clone();
        let mut subst = HashMap::new();
        while let Some(constraint) = worklist.pop() {
            let left = Self::substitute(constraint.left, &subst);
            let right = Self::substitute(constraint.right, &subst);
            match (&left, &right) {
                (Type::TypeVar(id), _) => {
                    println!("unify: {} => {}", id, right);
                    subst.insert(*id, right);
                }
                (_, Type::TypeVar(id)) => {
                    println!("unify: {} => {}", id, left);
                    subst.insert(*id, left);
                }
                (Type::Char, Type::Bool) => {} // panic!("Cannot unify char and bool"),
                _ => {}
            }
        }
        let mut final_subst = HashMap::new();
        for (k, _) in subst.iter() {
            final_subst.insert(*k, Self::substitute(Type::TypeVar(*k), &subst));
        }
        Ok(final_subst)
    }
}

#[cfg(test)]
mod tests {

    use crate::disasm::parser;

    use super::*;

    struct TestContext {
        binary: Vec<i128>,
        type_inference: TypeInference,
        program: ProgramAnalysis,
        result: HashMap<TypeVarId, Type>,
    }

    impl<'a> TestContext {
        fn new(code: &str) -> TestContext {
            let binary = parser::compile(code);
            let program: ProgramAnalysis = ProgramAnalysis::build(&binary);
            let mut type_inference = TypeInference::new();
            type_inference.generate_constaints_for_program(&program);
            let result = type_inference.unify().unwrap();
            program.list_program_with_types(&mut type_inference, &result);
            Self {
                binary,
                type_inference,
                program,
                result,
            }
        }

        fn assert_type(&self, addr: usize, expected: Type) {
            let Type::TypeVar(type_var) = self
                .type_inference
                .type_vars
                .iter()
                .filter(|(k, _)| matches!(k.ssa_arg.arg, Arg::Mem(a) if a as usize==addr))
                .max_by_key(|(k, _)| k.ssa_arg.version)
                .expect("No type variable found for address")
                .1
            else {
                panic!("No type variable found for address {}", addr);
            };
            let actual = self.result.get(type_var).unwrap();
            assert_eq!(
                *actual, expected,
                "Expected type {:?} but got {:?} for memory address {}",
                expected, actual, addr
            );
        }

        fn get_marker(&self, debug_marker: char) -> &Type {
            let Some(var) = self.type_inference.debug_markers.get(&debug_marker) else {
                panic!("No type variable found for debug marker '{}", debug_marker);
            };
            let res = self.type_inference.type_vars.get(&var).expect(&format!(
                "No type variable found for debug marker '{}",
                debug_marker
            ));
            match res {
                Type::TypeVar(type_var) => self.result.get(type_var).unwrap(),
                _ => panic!("Unexpected type for debug marker {}", debug_marker),
            }
        }

        fn assert_marker(&self, debug_marker: char, expected: Type) {
            let actual = self.get_marker(debug_marker);
            assert_eq!(
                *actual, expected,
                "Expected type {:?} but got {:?} for debug marker '{}",
                expected, actual, debug_marker
            );
        }
    }

    #[test]
    fn test_type_inference() {
        let ctx = TestContext::new(
            r#"
        R += 5000
        [3] = 'a [1] + [2]
        [R] = @res
        goto @f1
res:
        halt
f1:
        R += 4
        [21] = [R-1]
        if 'b [0] goto @f1
        R -= 4
        goto [R]

        "#,
        );
        ctx.assert_type(1, Type::Int);
        ctx.assert_marker('a', Type::Int);
        // ctx.assert_marker('b', Type::Bool);
    }

    #[test]
    fn test_boolean_comparison() {
        let ctx = TestContext::new(
            r#"
            R += 1000
            [1000] = [1001] < [1002]
        "#,
        );
        ctx.assert_type(1000, Type::Bool);
        ctx.assert_type(1001, Type::Int);
        ctx.assert_type(1002, Type::Int);
    }

    #[test]
    fn test_output_implies_char() {
        let ctx = TestContext::new(
            r#"
            R += 1000
            output [1001]
        "#,
        );
        ctx.assert_type(1001, Type::Char);
    }

    #[test]
    fn test_function_addr() {
        let ctx = TestContext::new(
            r#"
                R += 1000
                [1001] = [R-2]
                [R] = @ret
                goto [R-2]
                ret:
                halt

            "#,
        );
        ctx.assert_type(
            1001,
            Type::FunctionPointer {
                args: vec![],
                returns: vec![],
            },
        );
    }

    #[test]
    fn test_function_addr_with_debug() {
        let ctx = TestContext::new(
            r#"
                    R += 1000
                    'a [R+2] = [R-2]
                    'b [R+2] = 15
                    'c [R+2] = [R+2] + 5
                    [R] = @ret
                    goto [R-2]
            ret:
                    halt
                "#,
        );
        ctx.assert_marker(
            'a',
            Type::FunctionPointer {
                args: vec![],
                returns: vec![],
            },
        );
        ctx.assert_marker('b', Type::Int);
        ctx.assert_marker('c', Type::Int);
    }

    #[test]
    fn test_link_function_params_to_argument_types() {
        let ctx = TestContext::new(
            r#"
                R += 1000
                output('d [R-3])
                'a [R+1] = 65
                [R] = @ret
                goto @print
    ret:
                halt
    print:
                R += 4
                output('b [R-3])
                R -= 4
                goto [R]
            "#,
        );
        println!("program_info={:?}", ctx.program.function_infos);
        ctx.assert_marker('d', Type::Char);
        ctx.assert_marker('b', Type::Char);
        ctx.assert_marker('a', Type::Char);
    }
}
