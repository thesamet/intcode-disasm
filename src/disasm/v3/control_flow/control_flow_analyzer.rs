use std::collections::{HashMap, HashSet};

use dsl_macros_impl::build_expr;
use itertools::Itertools;
use log::trace;
use petgraph::visit::IntoNeighbors;

use crate::disasm::hlr::ast::{
    BinaryOperator, HlrAssignmentTarget, HlrExpression, HlrFunction, HlrGlobals, HlrProgram,
    HlrStatement, HlrVariable, Scope, UnaryOperator,
};
use crate::disasm::v3::cfg::{BlockView, FunctionView};
use crate::disasm::v3::lir::expression::ExpressionPathVisitor;
use crate::disasm::v3::lir::{
    BinaryOperator as LirBinaryOperator, Expression, ExpressionPath, Instruction, TypeVarPath,
    UnaryOperator as LirUnaryOperator,
};
use crate::disasm::v3::model::{HlrConstructionComplete, Model, VariableMergerComplete};
use crate::disasm::v3::ssa::types::VersionableMemoryKind;
use crate::disasm::v3::ssa::{SsaMemoryReference, VersionedMemoryReference};
use crate::disasm::v3::type_inference::{Type, StructDef};
use crate::disasm::v3::variable_analyzer::ClusterId;
use crate::disasm::v3::{BlockId, FunctionId, InstructionId, NextKind};
use crate::disasm::Error;
use crate::disasm::symbol_renaming::{StructId, UserDefs};

type Function<'a> = FunctionView<'a, VariableMergerComplete>;

#[derive(Debug)]
struct FunctionAnalysisContext {
    loops: HashMap<BlockId, LoopStructure>,
    ifs: HashMap<BlockId, BlockId>,
    in_loop: Option<LoopStructure>,
    in_if: Vec<(BlockId, BlockId)>,
    vars: HashSet<HlrVariable>,
}

impl FunctionAnalysisContext {
    fn new(loops: HashMap<BlockId, LoopStructure>, ifs: HashMap<BlockId, BlockId>) -> Self {
        Self {
            loops,
            ifs,
            in_loop: None,
            in_if: vec![],
            vars: HashSet::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LoopStructure {
    header: BlockId,    // loop entry point. 'continue' jumps here.
    jump_back: BlockId, // the furthest block that has a jump back to the header.
    exit: Option<BlockId>, // a block outside the loop that we possible jump to from the loop.
                        // if None, the loop is infinite. If not, 'break' jumps here.
}

pub struct ControlFlowStructureAnalyzer {
    model: Model<VariableMergerComplete>,
    globals: HlrGlobals,
}

struct GlobalVariableDiscovery<'a> {
    globals: &'a mut HlrGlobals,
    model: &'a Model<VariableMergerComplete>,
    base_type_var_path: TypeVarPath,
}

impl<'a> GlobalVariableDiscovery<'a> {
    fn new(
        base_type_var_path: TypeVarPath,
        model: &'a Model<VariableMergerComplete>,
        globals: &'a mut HlrGlobals,
    ) -> Self {
        Self {
            base_type_var_path,
            model,
            globals,
        }
    }

    fn run(&mut self, expr: &Expression<SsaMemoryReference>) -> Result<(), Error> {
        expr.visit(self, &ExpressionPath::root())
    }
}

impl<'a> ExpressionPathVisitor<SsaMemoryReference> for GlobalVariableDiscovery<'a> {
    type Return = ();
    type Error = Error;

    fn default_return(&mut self) -> Self::Return {}

    fn visit_constant(
        &mut self,
        path: &ExpressionPath,
        value: i128,
    ) -> Result<Self::Return, Self::Error> {
        let tv_id = self
            .model
            .type_inference_result()
            .get_type_id_for_path(&self.base_type_var_path.extending_path(path));
        let typ = self.model.type_inference_result().get_type_for_id(tv_id);
        let addr = if value < 0 {
            return Ok(());
        } else {
            value as usize
        };
        
        // Check if this address is defined as a global array in UserDefs
        if let Some((global_name, Some(global_type))) = self.model.user_defs().globals().get(&addr) {
            if let Type::Array { len, elem_type } = global_type {
                let image = &self.model.image_scanner_result().image;
                let array_expr = match elem_type.as_ref() {
                    Type::Struct(struct_id) => {
                        create_struct_array_expression(
                            addr,
                            *len,
                            *struct_id,
                            image,
                            self.model.user_defs(),
                        )
                    }
                    _ => {
                        // Use generic array formatting for all other types
                        create_generic_array_expression(
                            addr,
                            *len,
                            elem_type,
                            image,
                            self.model.user_defs(),
                        )
                    }
                };
                
                self.globals.insert(
                    addr,
                    (
                        HlrVariable {
                            name: global_name.clone(),
                            type_info: global_type.clone(),
                            scope: Scope::Global,
                        },
                        array_expr,
                    ),
                );
                return Ok(());
            }
            
            // Handle individual struct types
            if let Type::Struct(struct_id) = global_type {
                let image = &self.model.image_scanner_result().image;
                let struct_def = self.model.user_defs().get_struct_definitions().get(struct_id).unwrap();
                let struct_expr = format_struct_instance(
                    addr,
                    struct_def,
                    image,
                    self.model.user_defs(),
                );
                
                self.globals.insert(
                    addr,
                    (
                        HlrVariable {
                            name: global_name.clone(),
                            type_info: global_type.clone(),
                            scope: Scope::Global,
                        },
                        HlrExpression::String(struct_expr),
                    ),
                );
                return Ok(());
            }
        }
        
        if let Some(Type::CustomType(ct_id)) = typ.as_pointer() {
            let ct_name = self.model.user_defs().get_custom_type(*ct_id).unwrap();
            let image = &self.model.image_scanner_result().image;
            let len = image[addr];
            let r: String = image[(addr + 1)..(addr + (len as usize) + 1)]
                .iter()
                .enumerate()
                .map(|(i, &x)| (x + len + i as i128) as u8 as char)
                .collect();
            let name = self
                .model
                .user_defs()
                .get_global(addr)
                .cloned()
                .unwrap_or_else(|| format!("{}_{}", heck::AsShoutySnakeCase(ct_name), addr));
            self.globals.insert(
                addr,
                (
                    HlrVariable {
                        name,
                        type_info: typ,
                        scope: Scope::Global,
                    },
                    HlrExpression::String(r),
                ),
            );
        } else if let Type::Array { len, elem_type } = &typ {
            let image = &self.model.image_scanner_result().image;
            let name = self
                .model
                .user_defs()
                .get_global(addr)
                .cloned()
                .unwrap_or_else(|| format!("Array_{}", addr));
            
            let array_expr = match elem_type.as_ref() {
                Type::Struct(struct_id) => {
                    create_struct_array_expression(
                        addr,
                        *len,
                        *struct_id,
                        image,
                        self.model.user_defs(),
                    )
                }
                Type::Int => {
                    create_int_array_expression(addr, *len, image)
                }
                _ => {
                    // For other types, show a generic representation
                    HlrExpression::String(format!("[/* Array<{}; {:?}> */]", len, elem_type))
                }
            };
            
            self.globals.insert(
                addr,
                (
                    HlrVariable {
                        name,
                        type_info: typ.clone(),
                        scope: Scope::Global,
                    },
                    array_expr,
                ),
            );
        }
        Ok(())
    }

    fn visit_addressable(
        &mut self,
        _path: &ExpressionPath,
        addressable: &SsaMemoryReference,
        _: Option<Self::Return>,
    ) -> Result<Self::Return, Self::Error> {
        let Some(&addr) = addressable.as_versioned().and_then(|v| v.kind.as_memory()) else {
            return Ok(());
        };
        let tv_id = self
            .model
            .type_inference_result()
            .get_global_type_var_id(addr)
            .unwrap();
        let typ = self.model.type_inference_result().get_type_for_id(tv_id);

        let name = self
            .model
            .user_defs()
            .get_global(addr)
            .cloned()
            .unwrap_or_else(|| format!("Global{addr}"));
        let value: i128 = self.model.image_scanner_result().image[addr];
        self.globals.insert(
            addr,
            (
                HlrVariable {
                    name,
                    type_info: typ.clone(),
                    scope: Scope::Global,
                },
                HlrExpression::Constant(value, typ),
            ),
        );
        Ok(())
    }
}

// Helper struct for converting LIR Expression to HLR Expression using the Visitor pattern
struct HlrExpressionConverter<'a> {
    analyzer: &'a ControlFlowStructureAnalyzer,
    base_type_var_path: TypeVarPath,
}

impl<'a> HlrExpressionConverter<'a> {
    fn new(analyzer: &'a ControlFlowStructureAnalyzer, base_type_var_path: TypeVarPath) -> Self {
        Self {
            analyzer,
            base_type_var_path,
        }
    }
}

impl<'a> ExpressionPathVisitor<SsaMemoryReference> for HlrExpressionConverter<'a> {
    type Return = HlrExpression;

    type Error = Error;

    fn default_return(&mut self) -> Self::Return {
        todo!()
    }

    fn visit_constant(
        &mut self,
        path: &ExpressionPath,
        value: i128,
    ) -> Result<Self::Return, Self::Error> {
        // Type for Constant is derived from its path
        let tv_id = self
            .analyzer
            .model
            .type_inference_result()
            .get_type_id_for_path(&self.base_type_var_path.extending_path(path));
        let typ = self
            .analyzer
            .model
            .type_inference_result()
            .get_type_for_id(tv_id);
        Ok(self.analyzer.const_to_hlr(value, typ))
    }

    fn visit_addressable(
        &mut self,
        _path: &ExpressionPath,
        addressable: &SsaMemoryReference,
        deref_expr: Option<Self::Return>,
    ) -> Result<Self::Return, Self::Error> {
        match addressable {
            SsaMemoryReference::Versioned(VersionedMemoryReference {
                kind: VersionableMemoryKind::Memory(addr),
                ..
            }) => Ok(HlrExpression::Variable(
                self.analyzer
                    .globals
                    .get(addr)
                    .map(|(v, _)| v)
                    .cloned()
                    .unwrap_or_else(|| panic!("Could not find global {addr}")),
            )),
            SsaMemoryReference::Versioned(vmr) => {
                // The type of a VMR is inherently tied to the VMR itself,
                // not necessarily the path of the Expression::Addressable node.
                Ok(HlrExpression::Variable(self.analyzer.hlr_var(vmr)))
            }
            SsaMemoryReference::Deref(_) => Ok(HlrExpression::Deref(Box::new(deref_expr.unwrap()))),
        }
    }

    fn visit_binary(
        &mut self,
        path: &ExpressionPath,
        _: &Expression<SsaMemoryReference>,
        op: LirBinaryOperator,
        lhs: Self::Return,
        rhs: Self::Return,
    ) -> Result<Self::Return, Self::Error> {
        // Type for the result of a Binary operation is derived from its path
        let tv_id = self
            .analyzer
            .model
            .type_inference_result()
            .get_type_id_for_path(&self.base_type_var_path.extending_path(path));
        let result_type = self
            .analyzer
            .model
            .type_inference_result()
            .get_type_for_id(tv_id);

        let hlr_op = match op {
            LirBinaryOperator::Add => BinaryOperator::Add,
            LirBinaryOperator::Mul => BinaryOperator::Mul,
            LirBinaryOperator::Sub => BinaryOperator::Sub,
            LirBinaryOperator::LessThan => BinaryOperator::LessThan,
            LirBinaryOperator::LessThanOrEqual => BinaryOperator::LessThanOrEqual,
            LirBinaryOperator::GreaterThan => BinaryOperator::GreaterThan,
            LirBinaryOperator::GreaterThanOrEqual => BinaryOperator::GreaterThanOrEqual,
            LirBinaryOperator::Equals => BinaryOperator::Equals,
            LirBinaryOperator::NotEquals => BinaryOperator::NotEquals,
        };

        Ok(HlrExpression::BinaryOp {
            op: hlr_op,
            left: Box::new(lhs),
            right: Box::new(rhs),
            result_type,
        })
    }

    fn visit_unary(
        &mut self,
        _path: &ExpressionPath,
        op: LirUnaryOperator,
        arg: Self::Return,
    ) -> Result<Self::Return, Self::Error> {
        let hlr_op = match op {
            LirUnaryOperator::Not => UnaryOperator::LogicalNot,
            LirUnaryOperator::Minus => UnaryOperator::Minus,
        };
        Ok(HlrExpression::UnaryOperator {
            op: hlr_op,
            expr: Box::new(arg),
        })
    }

    fn visit_input(&mut self, _path: &ExpressionPath) -> Result<Self::Return, Self::Error> {
        Ok(HlrExpression::Input())
    }

    fn visit_debug_marker(
        &mut self,
        _path: &ExpressionPath,
        _marker: char,
        expr: Self::Return,
    ) -> Result<Self::Return, Self::Error> {
        // Effectively unwraps the marker, returning the HLR of the inner expression
        Ok(expr)
    }
}

impl ControlFlowStructureAnalyzer {
    fn new(model: Model<VariableMergerComplete>) -> Self {
        Self {
            model,
            globals: HlrGlobals::new(),
        }
    }

    pub fn run(
        model: Model<VariableMergerComplete>,
    ) -> Result<Model<HlrConstructionComplete>, Error> {
        ControlFlowStructureAnalyzer::new(model).recover_structures()
    }

    pub fn extract_global_variables(&mut self) -> Result<(), Error> {
        for (_, func) in self.model.functions() {
            for (_, block) in func.blocks() {
                for instr in &block.folded_ssa().instructions {
                    for (path, expr) in instr.collect_all_expressions().into_iter() {
                        let mut global_var_discovery =
                            GlobalVariableDiscovery::new(path, &self.model, &mut self.globals);
                        global_var_discovery.run(expr)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Recovers high-level control flow structures for the entire program.
    fn recover_structures(mut self) -> Result<Model<HlrConstructionComplete>, Error> {
        let mut hlr_functions = Vec::new();

        self.extract_global_variables()?;

        // Process each function in the program
        for (_, func) in self.model.functions() {
            // Get parameter types from function call analysis (if available)
            let hlr_function = self.analyze_function(func)?;

            hlr_functions.push(hlr_function);
        }

        // Create and store the HlrProgram
        let hlr_program = HlrProgram {
            functions: hlr_functions,
            globals: self.globals,
        };
        let updated = self.model.with_hlr_program(hlr_program);

        Ok(updated)
    }

    fn find_loops(
        func: Function,
        doms: &petgraph::algo::dominators::Dominators<BlockId>,
    ) -> HashMap<BlockId, LoopStructure> {
        let mut loops: HashMap<BlockId, LoopStructure> = HashMap::new();
        for node in func.all_block_ids() {
            // Detect when the node has a follower  that dominates it, that means the node loops
            // back to a loop header.
            for potential_header in func.neighbors(*node) {
                if doms.dominators(*node).unwrap().contains(&potential_header) {
                    let current_loop = loops.entry(potential_header).or_insert(LoopStructure {
                        header: potential_header,
                        jump_back: *node,
                        exit: None,
                    });
                    if *node > current_loop.jump_back {
                        current_loop.jump_back = *node;
                    }
                }
            }
        }
        for (_, lp) in loops.iter_mut() {
            let mut jump_outs = HashSet::new();
            let mut dfs = petgraph::visit::Dfs::new(&func, lp.header);
            while let Some(u) = dfs.next(&func) {
                for v in func.neighbors(u) {
                    if v > lp.jump_back {
                        jump_outs.insert(v);
                    }
                }
            }
            assert!(jump_outs.len() <= 2,);
            if jump_outs.len() == 2 {
                assert!(jump_outs.remove(&func.return_block().unwrap()));
            }
            lp.exit = jump_outs.iter().exactly_one().ok().cloned();
            trace!("Function_i={} has loop: {:?}", func.function_id(), lp);
        }
        loops
    }

    fn find_ifs(
        func: Function,
        post_doms: &Option<petgraph::algo::dominators::Dominators<BlockId>>,
    ) -> HashMap<BlockId, BlockId> {
        let mut ifs = HashMap::new();
        for node in func.all_block_ids() {
            let mut has_back_edge = false;
            let doms = petgraph::algo::dominators::simple_fast(func, func.entry_block());
            for potential_header in func.neighbors(*node) {
                if doms.dominators(*node).unwrap().contains(&potential_header) {
                    has_back_edge = true;
                }
            }
            if func.neighbors(*node).count() > 1 && !has_back_edge {
                let merge_point = post_doms
                    .as_ref()
                    .unwrap()
                    .immediate_dominator(*node)
                    .unwrap_or_else(|| panic!("No immediate dominator for node {node}"));
                ifs.insert(*node, merge_point);
                trace!(
                    "Function_i={} has if: {} -> {}",
                    func.function_id(),
                    node,
                    merge_point
                );
            }
        }
        ifs
    }

    fn make_analysis_context(func: Function) -> FunctionAnalysisContext {
        let doms = petgraph::algo::dominators::simple_fast(func, func.entry_block());

        let post_doms: Option<petgraph::algo::dominators::Dominators<BlockId>> =
            func.return_block().map(|return_point| {
                let rev = petgraph::visit::Reversed(func);

                petgraph::algo::dominators::simple_fast(&rev, return_point)
            });

        let loops = Self::find_loops(func, &doms);
        let ifs = Self::find_ifs(func, &post_doms);

        FunctionAnalysisContext::new(loops, ifs)
    }

    fn analyze_function(&self, func: Function) -> Result<HlrFunction, Error> {
        let mut context = Self::make_analysis_context(func);

        let args = self.model.type_inference_result().function_signatures[&func.function_id()]
            .args
            .iter()
            .map(|(t, _, _)| self.hlr_var(t))
            .collect_vec();

        // Add args to the context so they do not get "let" statements on
        // first write.
        for arg in &args {
            context.vars.insert(arg.clone());
        }
        let mut stmts = self.analyze_block(func, &mut context, func.entry_block(), None);
        stmts.extend(self.maybe_return_statement(func, true));
        let return_type = self.model.type_inference_result().function_signatures
            [&func.function_id()]
            .returns
            .iter()
            .map(|(t, _, _)| self.hlr_var(t))
            .collect_vec();

        let name = self
            .model
            .user_defs()
            .get_function_name(func.function_id())
            .cloned()
            .unwrap_or_else(|| format!("{}", func.function_id()));

        let hlr = HlrFunction {
            original_id: func.function_id(),
            name,
            args,
            return_type,
            body: stmts,
        };
        Ok(hlr)
    }

    fn analyze_block(
        &self,
        func: Function,
        context: &mut FunctionAnalysisContext,
        start: BlockId,
        end: Option<BlockId>,
    ) -> Vec<HlrStatement> {
        let mut current = start;
        let mut statements = vec![];
        while Some(current) != end {
            let block = func.block(&current);
            if let Some(discovered_loop) = context.loops.get(&current).cloned() {
                match context.in_loop {
                    // We are already processing a loop. We must be just starting to process it,
                    // so we require the loop we are on to be the same loop as the one in the context.
                    Some(existing_loop) => {
                        if existing_loop != discovered_loop {
                            // Found a different loop header while already processing `existing_loop`.
                            panic!("Nested loops not supported");
                        }
                    }
                    // Not currently processing a loop, so start processing this one.
                    None => {
                        context.in_loop = Some(discovered_loop);
                        let loop_body = self.analyze_block(func, context, current, None);
                        if let NextKind::Condition(cond) =
                            &func.block(&discovered_loop.jump_back).folded_ssa().next
                        {
                            assert!(cond.target_block == discovered_loop.header);
                            
                            let condition_expr = self.expr_to_hlr(
                                &cond.condition_operand,
                                TypeVarPath::if_cond(
                                    func.function_id(),
                                    cond.instruction_id,
                                ),
                            );
                            
                            // Check if the condition is already a boolean comparison
                            let loop_condition = match &condition_expr {
                                HlrExpression::BinaryOp { op, .. } if op.is_logical_operator() => {
                                    // Already a boolean expression, use it directly
                                    // Negate it if jump_if_true is false (we want to continue while true)
                                    if cond.jump_if_true {
                                        condition_expr
                                    } else {
                                        // Negate the comparison
                                        if let HlrExpression::BinaryOp { op, left, right, result_type } = condition_expr {
                                            HlrExpression::BinaryOp {
                                                op: op.logical_not(),
                                                left,
                                                right,
                                                result_type,
                                            }
                                        } else {
                                            unreachable!()
                                        }
                                    }
                                }
                                _ => {
                                    // Not a boolean comparison, compare to 0 as before
                                    let op = if cond.jump_if_true {
                                        BinaryOperator::NotEquals
                                    } else {
                                        BinaryOperator::Equals
                                    };
                                    HlrExpression::BinaryOp {
                                        op,
                                        left: Box::new(condition_expr),
                                        right: Box::new(HlrExpression::Constant(0, Type::Int)),
                                        result_type: Type::Bool,
                                    }
                                }
                            };
                            
                            statements.push(HlrStatement::DoWhile(loop_body, loop_condition));
                        } else {
                            // If the loop jumps to a different block, we need to
                            // negate the jump condition and make it a break.
                            statements.push(HlrStatement::Loop(loop_body));
                        }
                        return statements;
                    }
                }
            }
            if let Err(e) =
                self.translate_statements(context, func.function_id(), block, &mut statements)
            {
                panic!("Error translating statements: {e}");
            }
            if let Some(in_loop) = context.in_loop {
                if current == in_loop.jump_back {
                    // done processing the loop body. Jump back is handled by the caller.
                    break;
                }
            }
            match &block.folded_ssa().next {
                NextKind::Follows(next) => {
                    current = *next;
                }
                NextKind::Goto(addr) => {
                    match (context.in_loop, context.in_if.last(), func.return_block()) {
                        (Some(in_loop), _, _) if *addr == in_loop.header => {
                            statements.push(HlrStatement::Continue);
                            break;
                        }
                        (Some(in_loop), _, _) if Some(*addr) == in_loop.exit => {
                            statements.push(HlrStatement::Break);
                            break;
                        }
                        (_, _, Some(return_block)) if *addr == return_block => {
                            statements.extend(self.maybe_return_statement(func, false));
                            break;
                        }
                        (_, Some((_, merge_point)), _) if *addr == *merge_point => {
                            break;
                        }
                        _ => panic!(
                            "Goto unknown from block {} to {}. Return_block: {:?}",
                            current,
                            addr,
                            func.return_block()
                        ),
                    }
                }
                NextKind::FunctionCall(call) => {
                    let csi = self
                        .model
                        .function_call_analysis_result()
                        .blocks
                        .get(&call.calling_block)
                        .unwrap();
                    let Instruction::Call {
                        ref addr, ref args, ..
                    } = block
                        .folded_ssa()
                        .instructions
                        .iter()
                        .find(|i| i.id == call.instruction_id)
                        .unwrap()
                        .kind
                    else {
                        panic!("Expected function call instruction");
                    };
                    let fcall = HlrExpression::FunctionCall(
                        Box::new(self.expr_to_hlr(
                            addr,
                            TypeVarPath::call_address(func.function_id(), call.instruction_id),
                        )),
                        args.iter()
                            .enumerate()
                            .map(|(index, e)| {
                                self.expr_to_hlr(
                                    e,
                                    TypeVarPath::call_arg(
                                        func.function_id(),
                                        call.instruction_id,
                                        index,
                                    ),
                                )
                            })
                            .collect_vec(),
                    );
                    if csi.return_reads.is_empty() {
                        statements.push(HlrStatement::Assignment(
                            HlrAssignmentTarget::Ignored,
                            fcall,
                        ))
                    } else {
                        let rets = csi
                            .return_reads
                            .iter()
                            .sorted()
                            .map(|(_, v)| self.hlr_var(v))
                            .collect_vec();
                        statements.push(HlrStatement::VarDef(rets, fcall))
                    }

                    current = call.return_block;
                }
                NextKind::Condition(next_kind_cond) => {
                    let Instruction::If {
                        ref cond,
                        ref then_addr,
                        ref else_addr,
                        ..
                    } = block.folded_ssa().instructions.last().unwrap().kind
                    else {
                        panic!("Expected if instruction");
                    };
                    let cond_expr = self.expr_to_hlr(
                        cond,
                        TypeVarPath::if_cond(func.function_id(), next_kind_cond.instruction_id),
                    );
                    if let Some(in_loop) = context.in_loop {
                        if current != in_loop.jump_back {
                            // since it is not the final jump back in the block (caller handled that),
                            // then only the target can be a jump to the header or exit.
                            if *then_addr == in_loop.header {
                                statements.push(HlrStatement::If(
                                    cond_expr,
                                    vec![HlrStatement::Continue],
                                    vec![],
                                ));
                                current = *else_addr;
                                continue;
                            } else if Some(*then_addr) == in_loop.exit {
                                statements.push(HlrStatement::If(
                                    cond_expr,
                                    vec![HlrStatement::Break],
                                    vec![],
                                ));
                                current = *else_addr;
                                continue;
                            }
                        }
                    }
                    if Some(*then_addr) == func.return_block() {
                        statements.push(HlrStatement::If(
                            cond_expr,
                            vec![HlrStatement::Return(vec![])],
                            vec![],
                        ));
                        self.maybe_return_statement(func, false);
                        current = *else_addr;
                        continue;
                    }
                    if let Some(merge_point) = context.ifs.get(&current).cloned() {
                        context.in_if.push((current, merge_point));
                        let true_branch =
                            self.analyze_block(func, context, *then_addr, Some(merge_point));
                        let false_branch =
                            self.analyze_block(func, context, *else_addr, Some(merge_point));
                        context.in_if.pop();
                        if !true_branch.is_empty() {
                            statements.push(HlrStatement::If(cond_expr, true_branch, false_branch));
                        } else {
                            let cond = cond.clone();
                            let cond = build_expr! { !#cond };
                            let cond = self.expr_to_hlr(
                                &cond.simplify().unwrap_or(cond),
                                // TODO: This is likely wrong, if the expression has been simplified, the path may be out of sync with the expression
                                // used in the typevar.
                                TypeVarPath::if_cond(
                                    func.function_id(),
                                    next_kind_cond.instruction_id,
                                ),
                            );
                            statements.push(HlrStatement::If(cond, false_branch, true_branch));
                        }
                        current = merge_point;
                        continue;
                    }
                    unreachable!("Goto unknown from block {} to {}", current, *then_addr);
                }
                NextKind::Return => {
                    break;
                }
                NextKind::Halt => {
                    statements.push(HlrStatement::Halt);
                    break;
                }
                NextKind::Unknown => {
                    panic!("Unknown next kind for block {current}");
                }
            }
        }
        statements
    }

    fn var_expr(&self, var: &VersionedMemoryReference) -> HlrExpression {
        HlrExpression::Variable(self.hlr_var(var))
    }

    fn hlr_var(&self, var: &VersionedMemoryReference) -> HlrVariable {
        self.hlr_var_with_cluster_id(var).0
    }

    fn hlr_var_with_cluster_id(&self, var: &VersionedMemoryReference) -> (HlrVariable, ClusterId) {
        let vars = self.model.variable_merger_result();
        let cluster_id = vars
            .variable_to_cluster
            .get(var)
            .unwrap_or_else(|| panic!("Could not find cluster for variable {var:?}"));
        let cluster = &vars.clusters[cluster_id];
        let name = cluster.cluster_name.clone();
        let typ = self.var_type(var);
        (
            HlrVariable {
                name,
                type_info: typ,
                scope: match var.kind {
                    VersionableMemoryKind::Memory(_) => Scope::Global,
                    _ => Scope::Local,
                },
            },
            *cluster_id,
        )
    }

    fn expr_to_hlr(
        &self,
        expr: &Expression<SsaMemoryReference>,
        path: TypeVarPath,
    ) -> HlrExpression {
        let mut converter = HlrExpressionConverter::new(self, path);
        expr.visit(&mut converter, &ExpressionPath::root()).unwrap()
    }

    fn var_type(&self, var: &VersionedMemoryReference) -> Type {
        let vars = self.model.variable_merger_result();
        let cluster_id = vars.variable_to_cluster[var];
        let cluster = &vars.clusters[&cluster_id];
        cluster.inferred_type.clone()
    }

    fn translate_statements(
        &self,
        context: &mut FunctionAnalysisContext, // Mark context as potentially unused for now
        function_id: FunctionId,
        block: BlockView<'_, VariableMergerComplete>,
        statements: &mut Vec<HlrStatement>,
    ) -> Result<(), Error> {
        // Closure to create an HLR assignment target for a variable

        for instr in &block.folded_ssa().instructions {
            let stmt = match &instr.kind {
                Instruction::Assign { target, src, .. } => self.assign_or_def(
                    context,
                    function_id,
                    instr.id,
                    target,
                    self.expr_to_hlr(src, TypeVarPath::assignment_src(function_id, instr.id)),
                ),
                Instruction::Output(a) => HlrStatement::Output(
                    self.expr_to_hlr(a, TypeVarPath::output(function_id, instr.id)),
                ),
                Instruction::Call { .. }
                | Instruction::If { .. }
                | Instruction::Goto(_)
                | Instruction::Return
                | Instruction::Halt => continue,
            };
            statements.push(stmt);
        }
        Ok(())
    }

    // Returns some return statement if it's an early return or there are return values.
    fn maybe_return_statement(&self, func: Function, is_end: bool) -> Option<HlrStatement> {
        let rets = self.model.type_inference_result().function_signatures[&func.function_id()]
            .returns
            .iter()
            .map(|(t, _, _)| self.var_expr(t))
            .collect_vec();
        let has_rets = !rets.is_empty();
        let ret = HlrStatement::Return(rets);
        if !has_rets {
            if !is_end {
                Some(ret)
            } else {
                None
            }
        } else {
            Some(ret)
        }
    }

    fn assign_or_def(
        &self,
        context: &mut FunctionAnalysisContext,
        function_id: FunctionId,
        instruction_id: InstructionId,
        var: &SsaMemoryReference,
        expr: HlrExpression,
    ) -> HlrStatement {
        match var {
            SsaMemoryReference::Versioned(var) => {
                let hlr = self.hlr_var(var);
                if context.vars.contains(&hlr) {
                    HlrStatement::Assignment(HlrAssignmentTarget::Variable(hlr), expr)
                } else {
                    context.vars.insert(hlr.clone());
                    HlrStatement::VarDef(vec![hlr], expr)
                }
            }
            SsaMemoryReference::Deref(deref_expr) => HlrStatement::Assignment(
                HlrAssignmentTarget::Deref(self.expr_to_hlr(
                    deref_expr,
                    TypeVarPath::assignment_target_deref(function_id, instruction_id),
                )),
                expr,
            ),
        }
    }

    fn const_to_hlr(&self, c: i128, typ: Type) -> HlrExpression {
        let addr = if c < 0 {
            return HlrExpression::Constant(c, typ);
        } else {
            c as usize
        };
        if typ.is_function() {
            let function_id = FunctionId::new(addr);
            let name = self
                .model
                .user_defs()
                .get_function_name(function_id)
                .cloned()
                .unwrap_or_else(|| format!("{function_id}"));
            return HlrExpression::StaticFunctionReference(name);
        }
        if let Some((var, _)) = self.globals.get(&addr) {
            return HlrExpression::Variable(var.clone());
        }
        HlrExpression::Constant(c, typ)
    }
}

/// Create a structured HLR expression for a struct array using actual memory data
fn create_struct_array_expression(
    base_addr: usize,
    len: usize,
    struct_id: StructId,
    image: &[i128],
    user_defs: &UserDefs,
) -> HlrExpression {
    let Some(struct_def) = user_defs.get_struct(struct_id) else {
        return HlrExpression::String(format!("[/* Unknown struct {:?} */]", struct_id));
    };
    
    let mut result = String::new();
    result.push_str("[\n");
    
    for i in 0..len {
        if i > 0 {
            result.push_str(",\n");
        }
        
        let struct_addr = base_addr + i * struct_def.fields.len();
        result.push_str("    ");
        result.push_str(&format_struct_instance(struct_addr, struct_def, image, user_defs));
    }
    
    result.push_str("\n]");
    HlrExpression::String(result)
}

fn create_int_array_expression(
    base_addr: usize,
    len: usize,
    image: &[i128],
) -> HlrExpression {
    let mut result = String::new();
    result.push('[');
    
    for i in 0..len {
        if i > 0 {
            result.push_str(", ");
        }
        
        if base_addr + i < image.len() {
            result.push_str(&image[base_addr + i].to_string());
        } else {
            result.push_str(&format!("/* out of bounds: addr {} */", base_addr + i));
        }
    }
    
    result.push(']');
    HlrExpression::String(result)
}

/// Create a generic array expression that works for any element type
fn create_generic_array_expression(
    base_addr: usize,
    len: usize,
    elem_type: &Type,
    image: &[i128],
    user_defs: &UserDefs,
) -> HlrExpression {
    let mut result = String::new();
    result.push('[');
    
    for i in 0..len {
        if i > 0 {
            result.push_str(", ");
        }
        
        let element_value = image[base_addr + i];
        let formatted_value = format_field_value(
            element_value,
            &Some(elem_type.clone()),
            image,
            user_defs,
        );
        result.push_str(&formatted_value);
    }
    
    result.push(']');
    HlrExpression::String(result)
}

/// Format a single struct instance with proper indentation
fn format_struct_instance(
    struct_addr: usize,
    struct_def: &StructDef,
    image: &[i128],
    user_defs: &UserDefs,
) -> String {
    let mut result = String::new();
    result.push_str("{\n");
    
    for (field_idx, field) in struct_def.fields.iter().enumerate() {
        if field_idx > 0 {
            result.push_str(",\n");
        }
        
        let field_addr = struct_addr + field_idx;
        let field_value = image.get(field_addr).copied().unwrap_or(0);
        let formatted_value = format_field_value(field_value, &field.typ, image, user_defs);
        
        result.push_str(&format!("        {}: {}", field.name, formatted_value));
    }
    
    result.push_str("\n    }");
    result
}

/// Format a field value based on its type
fn format_field_value(
    field_value: i128,
    field_type: &Option<Type>,
    image: &[i128],
    user_defs: &UserDefs,
) -> String {
    let Some(Type::Pointer(inner_type)) = field_type else {
        return field_value.to_string();
    };
    
    let Type::CustomType(custom_type_id) = inner_type.as_ref() else {
        return field_value.to_string();
    };
    
    let Some(type_name) = user_defs.get_custom_type(*custom_type_id) else {
        return field_value.to_string();
    };
    
    if type_name != "EncodedString" {
        return field_value.to_string();
    }
    
    if field_value <= 0 || field_value as usize >= image.len() {
        return field_value.to_string();
    }
    
    format_encoded_string_shared(field_value as usize, image)
}

/// Shared function for formatting EncodedString (can be reused by pretty_print.rs)
fn format_encoded_string_shared(addr: usize, image: &[i128]) -> String {
    if addr >= image.len() {
        return "\"\"".to_string();
    }
    
    let len = image[addr] as usize;
    if addr + len >= image.len() {
        return "\"\"".to_string();
    }
    
    let chars: String = image[(addr + 1)..(addr + len + 1)]
        .iter()
        .enumerate()
        .map(|(i, &x)| (x + len as i128 + i as i128) as u8 as char)
        .collect();
    
    format!("\"{}\"", chars.escape_default())
}

/*
#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fmt::Display;
    use test_utils::*;

    use itertools::Itertools;
    use thiserror::Error;

    use crate::disasm::hlr::ast::HlrAssignmentTarget;
    use crate::disasm::hlr::ast::{
        test_utils, BinaryOperator, HlrExpression, HlrProgram, HlrStatement, HlrVariable,
    };
    struct VariableMapping {
        actual_to_expected: HashMap<String, String>,
        expected_to_actual: HashMap<String, String>,
    }

    #[derive(Error)]
    #[error("Comparison failed: {context}")]
    enum ComparisonError {
        #[error("At {context}: expected: {expected}, got: {actual}")]
        DifferentValues {
            actual: String,
            expected: String,
            context: String,
        },
        #[error("At {context}: expected: {expected}, got: {actual}")]
        UnsupportedComparison {
            actual: String,
            expected: String,
            context: String,
        },
    }

    impl std::fmt::Debug for ComparisonError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            std::fmt::Display::fmt(self, f)
        }
    }

    impl ComparisonError {
        fn new<T: Display>(actual: T, expected: T, context: &str) -> Self {
            Self::DifferentValues {
                actual: actual.to_string(),
                expected: expected.to_string(),
                context: context.to_string(),
            }
        }

        fn unsupported_comparison<T: Display>(actual: T, expected: T, context: &str) -> Self {
            Self::UnsupportedComparison {
                actual: actual.to_string(),
                expected: expected.to_string(),
                context: context.to_string(),
            }
        }
    }

    fn compare<T>(actual: T, expected: T, context: &str) -> Result<(), ComparisonError>
    where
        T: Display + PartialEq,
    {
        if expected == actual {
            Ok(())
        } else {
            Err(ComparisonError::new(actual, expected, context))
        }
    }

    type ComparisonResult = Result<(), ComparisonError>;

    impl VariableMapping {
        fn new() -> Self {
            Self {
                actual_to_expected: HashMap::new(),
                expected_to_actual: HashMap::new(),
            }
        }

        fn map_variable(
            &mut self,
            actual_name: &str,
            expected_name: &str,
            actual_type: &Type,
            expected_type: &Type,
            context: &str,
        ) -> ComparisonResult {
            compare(
                actual_type,
                expected_type,
                &format!("{}:Variable types don't match", context),
            )?;

            // Check if we already have a mapping
            if let Some(mapped_expected) = self.actual_to_expected.get(actual_name) {
                return compare(
                    mapped_expected,
                    &expected_name.to_string(),
                    &format!(
                        "{}:Variable name mapping inconsistent based on prior usage",
                        context
                    ),
                );
            }

            if let Some(mapped_actual) = self.expected_to_actual.get(expected_name) {
                return compare(
                    mapped_actual,
                    &actual_name.to_string(),
                    &format!(
                        "{}:Variable name mapping inconsistent based on prior usage",
                        context
                    ),
                );
            }

            // Create a new mapping
            self.actual_to_expected
                .insert(actual_name.to_string(), expected_name.to_string());
            self.expected_to_actual
                .insert(expected_name.to_string(), actual_name.to_string());
            Ok(())
        }
    }

    // Assertion functions
    fn assert_hlr_programs_equivalent(
        actual: &HlrProgram,
        expected: &HlrProgram,
    ) -> ComparisonResult {
        compare(
            actual.functions.len(),
            expected.functions.len(),
            "Different number of functions",
        )?;

        // Create a map of function IDs to functions for both actual and expected
        let actual_funcs: HashMap<_, _> = actual
            .functions
            .iter()
            .map(|f| (f.original_id, f))
            .collect();
        let expected_funcs: HashMap<_, _> = expected
            .functions
            .iter()
            .map(|f| (f.original_id, f))
            .collect();

        // Check that both have the same set of function IDs
        compare(
            actual_funcs.keys().sorted().join(", "),
            expected_funcs.keys().sorted().join(", "),
            "Function IDs don't match",
        )?;

        // Compare functions with the same ID
        for (id, expected_func) in expected_funcs.iter() {
            let actual_func = actual_funcs.get(id).unwrap();
            let mut mapping = VariableMapping::new();
            assert_statements_equivalent(
                &actual_func.body,
                &expected_func.body,
                &mut mapping,
                &format!("Function[{}]", id),
            )?;
        }
        Ok(())
    }

    fn assert_statements_equivalent(
        actual: &[HlrStatement],
        expected: &[HlrStatement],
        mapping: &mut VariableMapping,
        context: &str,
    ) -> ComparisonResult {
        compare(
            actual.len(),
            expected.len(),
            &format!("{}: Different number of statements", context),
        )?;
        for (i, (actual_stmt, expected_stmt)) in actual.iter().zip(expected.iter()).enumerate() {
            let stmt_context = format!("{}:Statement[{}]", context, i);

            match (actual_stmt, expected_stmt) {
                (
                    HlrStatement::Assignment(actual_target, actual_expr),
                    HlrStatement::Assignment(expected_target, expected_expr),
                ) => {
                    assert_targets_equivalent(
                        actual_target,
                        expected_target,
                        mapping,
                        &format!("{}:Target", stmt_context),
                    )?;
                    assert_expressions_equivalent(
                        actual_expr,
                        expected_expr,
                        mapping,
                        &format!("{}:Expression", stmt_context),
                    )?;
                }
                (
                    HlrStatement::VarDef(actual_var, actual_expr),
                    HlrStatement::VarDef(expected_var, expected_expr),
                ) => {
                    if actual_var.len() != expected_var.len() {
                        Err(ComparisonError::unsupported_comparison(
                            format!("{:?}", actual_var),
                            format!("{:?}", expected_var),
                            &format!("{}:Variable types don't match", stmt_context),
                        ))?
                    }
                    for (i, (actual_var, expected_var)) in
                        actual_var.iter().zip(expected_var.iter()).enumerate()
                    {
                        assert_var_equivalent(
                            actual_var,
                            expected_var,
                            mapping,
                            &format!("{}:Expression[{}]", stmt_context, i),
                        )?;
                    }
                    assert_expressions_equivalent(
                        actual_expr,
                        expected_expr,
                        mapping,
                        &format!("{}:Expression", stmt_context),
                    )?;
                }
                (
                    HlrStatement::If(actual_cond, actual_then, actual_else),
                    HlrStatement::If(expected_cond, expected_then, expected_else),
                ) => {
                    assert_expressions_equivalent(
                        actual_cond,
                        expected_cond,
                        mapping,
                        &format!("{}:Condition", stmt_context),
                    )?;
                    assert_statements_equivalent(
                        actual_then,
                        expected_then,
                        mapping,
                        &format!("{}:ThenBranch", stmt_context),
                    )?;
                    assert_statements_equivalent(
                        actual_else,
                        expected_else,
                        mapping,
                        &format!("{}:ElseBranch", stmt_context),
                    )?;
                }
                (HlrStatement::Loop(actual_body), HlrStatement::Loop(expected_body)) => {
                    assert_statements_equivalent(
                        actual_body,
                        expected_body,
                        mapping,
                        &format!("{}:LoopBody", stmt_context),
                    )?;
                }
                (HlrStatement::Output(actual_expr), HlrStatement::Output(expected_expr)) => {
                    assert_expressions_equivalent(
                        actual_expr,
                        expected_expr,
                        mapping,
                        &format!("{}:Output", stmt_context),
                    )?;
                }
                (HlrStatement::Return(actual_exprs), HlrStatement::Return(expected_exprs)) => {
                    compare(
                        actual_exprs.len(),
                        expected_exprs.len(),
                        &format!("{}:Return: expression count mismatch", stmt_context),
                    )?;
                    for (j, (a, e)) in actual_exprs.iter().zip(expected_exprs.iter()).enumerate() {
                        assert_expressions_equivalent(
                            a,
                            e,
                            mapping,
                            &format!("{}:Return[{}]", stmt_context, j),
                        )?;
                    }
                }
                (HlrStatement::Halt, HlrStatement::Halt) => {}
                (HlrStatement::Continue, HlrStatement::Continue) => {}
                (HlrStatement::Break, HlrStatement::Break) => {}
                (
                    HlrStatement::DoWhile(actual_body, actual_cond),
                    HlrStatement::DoWhile(expected_body, expected_cond),
                ) => {
                    assert_statements_equivalent(
                        actual_body,
                        expected_body,
                        mapping,
                        &format!("{}:DoWhileBody", stmt_context),
                    )?;
                    assert_expressions_equivalent(
                        actual_cond,
                        expected_cond,
                        mapping,
                        &format!("{}:DoWhileCond", stmt_context),
                    )?
                }

                _ => Err(ComparisonError::unsupported_comparison(
                    format!("{:?}", actual_stmt),
                    format!("{:?}", expected_stmt),
                    &format!("{}:Statement types don't match", stmt_context),
                ))?,
            }
        }
        Ok(())
    }

    fn assert_targets_equivalent(
        actual: &HlrAssignmentTarget,
        expected: &HlrAssignmentTarget,
        mapping: &mut VariableMapping,
        context: &str,
    ) -> ComparisonResult {
        match (actual, expected) {
            (
                HlrAssignmentTarget::Variable(actual_var),
                HlrAssignmentTarget::Variable(expected_var),
            ) => {
                assert_var_equivalent(actual_var, expected_var, mapping, context)?;
            }
            (
                HlrAssignmentTarget::Deref(actual_expr),
                HlrAssignmentTarget::Deref(expected_expr),
            ) => assert_expressions_equivalent(
                actual_expr,
                expected_expr,
                mapping,
                &format!("{}:Deref", context),
            )?,
            (HlrAssignmentTarget::Ignored, HlrAssignmentTarget::Ignored) => (),
            _ => {
                Err(ComparisonError::unsupported_comparison(
                    format!("{:?}", actual),
                    format!("{:?}", expected),
                    &format!("{}:Assignment target types don't match", context),
                ))?;
            }
        }
        Ok(())
    }

    fn assert_var_equivalent(
        actual: &HlrVariable,
        expected: &HlrVariable,
        mapping: &mut VariableMapping,
        context: &str,
    ) -> ComparisonResult {
        compare(
            &actual.type_info,
            &expected.type_info,
            &format!("{}:Variable types don't match", context),
        )?;

        mapping.map_variable(
            &actual.name,
            &expected.name,
            &actual.type_info,
            &expected.type_info,
            context,
        )?;
        Ok(())
    }

    fn assert_expressions_equivalent(
        actual: &HlrExpression,
        expected: &HlrExpression,
        mapping: &mut VariableMapping,
        context: &str,
    ) -> ComparisonResult {
        match (actual, expected) {
            (HlrExpression::Variable(actual_var), HlrExpression::Variable(expected_var)) => {
                assert_eq!(
                    &actual_var.type_info, &expected_var.type_info,
                    "{}:Variable types don't match: {:?} vs {:?}",
                    context, actual_var.type_info, expected_var.type_info
                );

                mapping.map_variable(
                    &actual_var.name,
                    &expected_var.name,
                    &actual_var.type_info,
                    &expected_var.type_info,
                    context,
                )?
            }
            (
                HlrExpression::Constant(actual_val, actual_type),
                HlrExpression::Constant(expected_val, expected_type),
            ) => {
                assert_eq!(
                    actual_val, expected_val,
                    "{}:Constant values don't match: {} vs {}",
                    context, actual_val, expected_val
                );
                compare(
                    &actual_val,
                    &expected_val,
                    &format!("{}:Constant values don't match", context),
                )?;
                compare(
                    &actual_type,
                    &expected_type,
                    &format!("{}:Constant types don't match", context),
                )?
            }
            (
                HlrExpression::BinaryOp {
                    op: actual_op,
                    left: actual_left,
                    right: actual_right,
                    result_type: actual_type,
                },
                HlrExpression::BinaryOp {
                    op: expected_op,
                    left: expected_left,
                    right: expected_right,
                    result_type: expected_type,
                },
            ) => {
                compare(
                    actual_op,
                    expected_op,
                    &format!("{}:Binary operators don't match", context),
                )?;
                compare(
                    actual_type,
                    expected_type,
                    &format!("{}:Result types don't match", context),
                )?;
                assert_expressions_equivalent(
                    actual_left,
                    expected_left,
                    mapping,
                    &format!("{}:Left", context),
                )?;
                assert_expressions_equivalent(
                    actual_right,
                    expected_right,
                    mapping,
                    &format!("{}:Right", context),
                )?
            }
            (HlrExpression::Deref(actual_expr), HlrExpression::Deref(expected_expr)) => {
                assert_expressions_equivalent(
                    actual_expr,
                    expected_expr,
                    mapping,
                    &format!("{}:Deref", context),
                )?
            }
            (HlrExpression::Input(), HlrExpression::Input()) => {}
            (
                HlrExpression::FunctionCall(actual_func, actual_args),
                HlrExpression::FunctionCall(expected_func, expected_args),
            ) => {
                assert_expressions_equivalent(
                    actual_func,
                    expected_func,
                    mapping,
                    &format!("{}:FunctionCall", context),
                )?;
                for (j, (a, e)) in actual_args.iter().zip(expected_args.iter()).enumerate() {
                    assert_expressions_equivalent(
                        a,
                        e,
                        mapping,
                        &format!("{}:Arg[{}]", context, j),
                    )?;
                }
            }
            _ => Err(ComparisonError::unsupported_comparison(
                format!("{:?}", actual),
                format!("{:?}", expected),
                &format!("{}:Expression types don't match", context),
            ))?,
        }
        Ok(())
    }

    use crate::disasm::test_utils::TestContextBuilder;
    use crate::disasm::v3::model::HlrConstructionComplete;
    use crate::disasm::v3::type_inference::Type;

    #[test]
    fn test_simple_sequential() -> ComparisonResult {
        let assembly = r#"
            R += 100           ; Initial R adjustment for main function
            [3] = 1 + 2        ; Add 1+2 -> mem[3]
            [5] = 3 + 4        ; Add 3+4 -> mem[5]
            halt               ; Halt
        "#;

        let ctx = HlrConstructionComplete::test_context(assembly).unwrap();

        // Create expected HLR program using our helper functions
        let expected = hlr_program(vec![hlr_function(
            0,
            vec![
                hlr_vardef(
                    hlr_var("ptr1", Type::Any),
                    hlr_binop(
                        BinaryOperator::Add,
                        hlr_const(1, Type::Int),
                        hlr_const(2, Type::Int),
                        Type::Any,
                    ),
                ),
                hlr_vardef(
                    hlr_var("ptr2", Type::Any),
                    hlr_binop(
                        BinaryOperator::Add,
                        hlr_const(3, Type::Int),
                        hlr_const(4, Type::Int),
                        Type::Any,
                    ),
                ),
                HlrStatement::Halt,
            ],
        )]);

        assert_hlr_programs_equivalent(ctx.model.hlr_program(), &expected)
    }

    #[test]
    fn test_if_else() -> ComparisonResult {
        let assembly = r#"
            R += 100           ; Initial R adjustment for main function
            [3] = 2 * 3        ; x = 1 + 2
            [4] = [3] == 3     ; y = (x == 3)
            if [4] goto @then  ; if y then goto label_then
            [7] = 5 * 6        ; z = 5 + 6 (else branch)
            goto @end          ; goto label_end
            then:
            [7] = 7 * 8        ; z = 7 + 8 (then branch)
            end:
            R -= 100
            goto [R]
        "#;

        let ctx = HlrConstructionComplete::test_context(assembly).unwrap();

        // Create expected HLR program
        let expected = hlr_program(vec![hlr_function(
            0,
            vec![
                hlr_vardef(
                    hlr_var("x", Type::Int),
                    hlr_binop(
                        BinaryOperator::Mul,
                        hlr_const(2, Type::Int),
                        hlr_const(3, Type::Int),
                        Type::Int,
                    ),
                ),
                hlr_vardef(
                    hlr_var("y", Type::Bool),
                    hlr_binop(
                        BinaryOperator::Equals,
                        hlr_var_expr("x", Type::Int),
                        hlr_const(3, Type::Int),
                        Type::Bool,
                    ),
                ),
                hlr_if(
                    hlr_binop(
                        BinaryOperator::NotEquals,
                        hlr_var_expr("y", Type::Bool),
                        hlr_const(0, Type::Int),
                        Type::Bool,
                    ),
                    // Then branch
                    vec![hlr_vardef(
                        hlr_var("w", Type::Int), // potential bug since we use different variables here.
                        hlr_binop(
                            BinaryOperator::Mul,
                            hlr_const(7, Type::Int),
                            hlr_const(8, Type::Int),
                            Type::Int,
                        ),
                    )],
                    // Else branch
                    vec![
                        hlr_vardef(
                            hlr_var("z", Type::Int),
                            hlr_binop(
                                BinaryOperator::Mul,
                                hlr_const(5, Type::Int),
                                hlr_const(6, Type::Int),
                                Type::Int,
                            ),
                        ),
                        hlr_return(vec![]),
                    ],
                ),
            ],
        )]);

        assert_hlr_programs_equivalent(ctx.model.hlr_program(), &expected)
    }

    #[test]
    fn test_loop() -> ComparisonResult {
        let assembly = r#"
            R += 100                  ;  0: Initial R adjustment for main function
            [R-1] = 0                 ;  2: i = 0
            loop_start:
            [R-2] = [R-1] < 10        ;  6: cond = (i < 10)
            if ![R-2] goto @loop_end  ; 10: if cond == 0 goto loop_end
            [R-1] = [R-1] + 1         ; 13: i = i + 1
            goto @loop_start          ; 17: goto loop_start
            loop_end:
            R -= 100                  ; 20
            goto [R]                  ; 21
            "#;

        let ctx = HlrConstructionComplete::test_context(assembly).unwrap();

        // Create expected HLR program
        let expected = hlr_program(vec![hlr_function(
            0,
            vec![
                hlr_vardef(hlr_var("i", Type::Int), hlr_const(0, Type::Int)),
                hlr_loop(vec![
                    hlr_vardef(
                        hlr_var("tmp", Type::Bool),
                        hlr_binop(
                            BinaryOperator::LessThan,
                            hlr_var_expr("i", Type::Int),
                            hlr_const(10, Type::Int),
                            Type::Bool,
                        ),
                    ),
                    hlr_if(
                        hlr_binop(
                            BinaryOperator::Equals,
                            hlr_var_expr("tmp", Type::Bool),
                            hlr_const(0, Type::Int),
                            Type::Bool,
                        ),
                        vec![HlrStatement::Break],
                        vec![],
                    ),
                    hlr_assign(
                        hlr_var_target("i", Type::Int),
                        hlr_binop(
                            BinaryOperator::Add,
                            hlr_var_expr("i", Type::Int),
                            hlr_const(1, Type::Int),
                            Type::Int,
                        ),
                    ),
                ]),
            ],
        )]);

        assert_hlr_programs_equivalent(ctx.model.hlr_program(), &expected)
    }

    #[test]
    fn test_do_while() -> ComparisonResult {
        let assembly = r#"
            R += 100
            [R-1] = 0
            loop_start:
            output([R-1])
            [R-1] = [R-1] + 1
            [R-2] = [R-1] < 10
            if [R-2] goto @loop_start
            output(10)
            R -= 100
            goto [R]
            "#;

        let ctx = HlrConstructionComplete::test_context(assembly).unwrap();

        // Create expected HLR program
        let expected = hlr_program(vec![hlr_function(
            0,
            vec![
                hlr_vardef(hlr_var("i", Type::Char), hlr_const(0, Type::Char)),
                hlr_do_while(
                    vec![
                        HlrStatement::Output(hlr_var_expr("i", Type::Char)),
                        hlr_assign(
                            hlr_var_target("i", Type::Char),
                            hlr_binop(
                                BinaryOperator::Add,
                                hlr_var_expr("i", Type::Char),
                                hlr_const(1, Type::Int),
                                Type::Char,
                            ),
                        ),
                        hlr_vardef(
                            hlr_var("tmp", Type::Bool),
                            hlr_binop(
                                BinaryOperator::LessThan,
                                hlr_var_expr("i", Type::Char),
                                hlr_const(10, Type::Int),
                                Type::Bool,
                            ),
                        ),
                    ],
                    hlr_binop(
                        BinaryOperator::NotEquals,
                        hlr_var_expr("tmp", Type::Bool),
                        hlr_const(0, Type::Int),
                        Type::Bool,
                    ),
                ),
            ],
        )]);

        assert_hlr_programs_equivalent(ctx.model.hlr_program(), &expected)
    }

    #[test]
    fn test_input_output() -> ComparisonResult {
        let assembly = r#"
            R += 100           ; Initial R adjustment for main function
            INPUT [1]          ; x = input()
            [2] = [1] + 10     ; y = x + 10
            output([2])        ; output(y)
            halt               ; Halt
        "#;

        let ctx = HlrConstructionComplete::test_context(assembly).unwrap();

        // Create expected HLR program with matching types
        let expected = hlr_program(vec![hlr_function(
            0,
            vec![
                hlr_vardef(hlr_var("m1", Type::Int), hlr_input()),
                hlr_vardef(
                    hlr_var("m2", Type::Char),
                    hlr_binop(
                        BinaryOperator::Add,
                        hlr_var_expr("m1", Type::Int),
                        hlr_const(10, Type::Int),
                        Type::Char,
                    ),
                ),
                hlr_output(hlr_var_expr("m2", Type::Char)),
                HlrStatement::Halt,
            ],
        )]);

        assert_hlr_programs_equivalent(ctx.model.hlr_program(), &expected)
    }

    #[test]
    fn test_pointer_operations() -> ComparisonResult {
        let assembly = r#"
            R += 100           ; Initial R adjustment for main function
            ptr = 100          ; ptr = 100 (address)
            [R+1] = *ptr       ; x = *ptr (value at address 100)
            [R+2] = [R+1] + 5  ; y = x + 5
            halt               ; Halt
        "#;

        let ctx = HlrConstructionComplete::test_context(assembly).unwrap();

        // Create expected HLR program
        let expected = hlr_program(vec![hlr_function(
            0,
            vec![
                hlr_vardef(
                    hlr_var("ptr1", Type::Pointer(Box::new(Type::Any))),
                    hlr_const(100, Type::Int),
                ),
                hlr_vardef(
                    hlr_var("local1", Type::Any),
                    hlr_deref(hlr_var_expr("ptr1", Type::Pointer(Box::new(Type::Any)))),
                ),
                hlr_vardef(
                    hlr_var("local2", Type::Any),
                    hlr_binop(
                        BinaryOperator::Add,
                        hlr_var_expr("local1", Type::Any),
                        hlr_const(5, Type::Int),
                        Type::Any,
                    ),
                ),
                HlrStatement::Halt,
            ],
        )]);

        assert_hlr_programs_equivalent(ctx.model.hlr_program(), &expected)
    }

    #[test]
    fn test_function_call() -> ComparisonResult {
        let assembly = r#"
            ; Main function
            R += 100           ; Initial R adjustment for main function
            [R+1] = 5          ; Set argument
            [R] = @return_addr ; Set return address
            goto @func         ; Call function
            return_addr:
            output([R+1])      ; Output return value
            halt

            ; Function that adds 5 to its input
            func:
            R += 3             ; Adjust stack for local variables
            [R-2] = [R-2] + 5  ; result = arg + 5
            R -= 3             ; Restore stack
            goto [R]           ; Return
        "#;

        let ctx = HlrConstructionComplete::test_context(assembly).unwrap();

        // Create expected HLR program (simplified for this test)
        let expected = hlr_program(vec![
            hlr_function(
                0,
                vec![
                    hlr_vardef(hlr_var("arg", Type::Int), hlr_const(5, Type::Int)),
                    hlr_vardef(
                        hlr_var("result", Type::Char),
                        hlr_function_call(hlr_const(16, Type::Int), vec![]),
                    ),
                    hlr_output(hlr_var_expr("result", Type::Char)),
                    HlrStatement::Halt,
                ],
            ),
            hlr_function(
                16,
                vec![
                    hlr_assign(
                        hlr_var_target("arg1", Type::Char),
                        hlr_binop(
                            BinaryOperator::Add,
                            hlr_var_expr("arg1", Type::Char),
                            hlr_const(5, Type::Int),
                            Type::Char,
                        ),
                    ),
                    hlr_return(vec![hlr_var_expr("arg1", Type::Char)]),
                ],
            ),
        ]);

        assert_hlr_programs_equivalent(ctx.model.hlr_program(), &expected)
    }

    #[test]
    fn test_nested_if_else() -> ComparisonResult {
        let _assembly = r#"
            R += 100                      ; 0: Initial R adjustment for main function
            [R-1] = 10                    ; 2: x = 10
            [R-2] = [R-1] < 5             ; 6: cond1 = (x < 5)
            if ![R-2] goto @else_outer    ; 10: if !cond1 goto else_outer

            ; Then branch of outer if
            [R-3] = [R-1] < 15            ; 13: cond2 = (x < 15)
            if ![R-3] goto @else_inner    ; 17: if !cond2 goto else_inner

            ; Then branch of inner if
            [R-4] = 1                     ; 20: result = 1
            goto @end_inner               ; 24:

            else_inner:
            ; Else branch of inner if
            [R-4] = 2                     ; 27: result = 2

            end_inner:
            goto @end_outer               ; 31:

            else_outer:
            ; Else branch of outer if
            [R-4] = 3                     ; 34: result = 3

            end_outer:
            output([R-4])                 ; 38: output(result)
            R -= 100                      ; 40:
            goto [R]                      ; 42:
        "#;

        let ctx = HlrConstructionComplete::test_context(_assembly).unwrap();

        // Create expected HLR program
        let expected = hlr_program(vec![hlr_function(
            0,
            vec![
                hlr_vardef(hlr_var("x", Type::Int), hlr_const(10, Type::Int)),
                hlr_vardef(
                    hlr_var("cond", Type::Bool),
                    hlr_binop(
                        BinaryOperator::LessThan,
                        hlr_var_expr("x", Type::Int),
                        hlr_const(5, Type::Int),
                        Type::Bool,
                    ),
                ),
                hlr_if(
                    // Then branch of outer if
                    hlr_binop(
                        BinaryOperator::Equals,
                        hlr_var_expr("cond", Type::Bool),
                        hlr_const(0, Type::Int),
                        Type::Bool,
                    ),
                    vec![hlr_vardef(
                        hlr_var("result", Type::Char),
                        hlr_const(3, Type::Char),
                    )],
                    vec![
                        hlr_vardef(
                            hlr_var("cond2", Type::Bool),
                            hlr_binop(
                                BinaryOperator::LessThan,
                                hlr_var_expr("x", Type::Int),
                                hlr_const(15, Type::Int),
                                Type::Bool,
                            ),
                        ),
                        hlr_if(
                            hlr_binop(
                                BinaryOperator::Equals,
                                hlr_var_expr("cond2", Type::Bool),
                                hlr_const(0, Type::Int),
                                Type::Bool,
                            ),
                            // Then branch of inner if
                            vec![hlr_assign(
                                hlr_var_target("result", Type::Char),
                                hlr_const(2, Type::Char),
                            )],
                            // Else branch of inner if
                            vec![hlr_assign(
                                hlr_var_target("result", Type::Char),
                                hlr_const(1, Type::Char),
                            )],
                        ),
                    ],
                    // Else branch of outer if
                ),
                hlr_output(hlr_var_expr("result", Type::Char)),
            ],
        )]);
        assert_hlr_programs_equivalent(ctx.model.hlr_program(), &expected)
    }
}
*/
