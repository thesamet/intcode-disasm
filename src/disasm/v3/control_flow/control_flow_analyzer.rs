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
use crate::disasm::v3::type_inference::Type;
use crate::disasm::v3::variable_analyzer::ClusterId;
use crate::disasm::v3::{BlockId, FunctionId, InstructionId, NextKind};
use crate::disasm::{Error, SymbolRenaming};

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

pub struct ControlFlowStructureAnalyzer<'a> {
    model: Model<VariableMergerComplete>,
    symbol_renaming: &'a SymbolRenaming,
    globals: HlrGlobals,
}

struct GlobalVariableDiscovery<'a> {
    globals: &'a mut HlrGlobals,
    symbol_renaming: &'a SymbolRenaming,
    model: &'a Model<VariableMergerComplete>,
    base_type_var_path: TypeVarPath,
}

impl<'a> GlobalVariableDiscovery<'a> {
    fn new(
        base_type_var_path: TypeVarPath,
        symbol_renaming: &'a SymbolRenaming,
        model: &'a Model<VariableMergerComplete>,
        globals: &'a mut HlrGlobals,
    ) -> Self {
        Self {
            base_type_var_path,
            globals,
            symbol_renaming,
            model,
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
        if let Some(Type::CustomType(ct_id)) = typ.as_pointer() {
            let ct_name = self.symbol_renaming.get_custom_type(*ct_id).unwrap();
            let image = &self.model.image_scanner_result().image;
            let len = image[addr];
            let r: String = image[(addr + 1)..(addr + (len as usize) + 1)]
                .iter()
                .enumerate()
                .map(|(i, &x)| (x as i128 + len as i128 + i as i128) as u8 as char)
                .collect();
            let name = self
                .symbol_renaming
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
        }
        Ok(())
    }

    fn visit_addressable(
        &mut self,
        path: &ExpressionPath,
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
            .symbol_renaming
            .get_global(addr)
            .cloned()
            .unwrap_or_else(|| format!("Global{}", addr));
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
    analyzer: &'a ControlFlowStructureAnalyzer<'a>,
    base_type_var_path: TypeVarPath,
}

impl<'a> HlrExpressionConverter<'a> {
    fn new(
        analyzer: &'a ControlFlowStructureAnalyzer<'a>,
        base_type_var_path: TypeVarPath,
    ) -> Self {
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
                    .get(&addr)
                    .map(|(v, _)| v)
                    .cloned()
                    .unwrap_or_else(|| panic!("Could not find global {}", addr)),
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

impl<'a> ControlFlowStructureAnalyzer<'a> {
    fn new(model: Model<VariableMergerComplete>, symbol_renaming: &'a SymbolRenaming) -> Self {
        Self {
            model,
            symbol_renaming,
            globals: HlrGlobals::new(),
        }
    }

    pub fn run(
        model: Model<VariableMergerComplete>,
        symbol_renaming: &'a SymbolRenaming,
    ) -> Result<Model<HlrConstructionComplete>, Error> {
        ControlFlowStructureAnalyzer::new(model, symbol_renaming).recover_structures()
    }

    pub fn extract_global_variables(&mut self) -> Result<(), Error> {
        for (_, func) in self.model.functions() {
            for (_, block) in func.blocks() {
                for instr in &block.folded_ssa().instructions {
                    for (path, expr) in instr.collect_all_expressions().into_iter() {
                        let mut global_var_discovery = GlobalVariableDiscovery::new(
                            path,
                            self.symbol_renaming,
                            &self.model,
                            &mut self.globals,
                        );
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
                    .unwrap_or_else(|| panic!("No immediate dominator for node {}", node));
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
            .symbol_renaming
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
                            &func.block(&discovered_loop.jump_back).ssa().next
                        {
                            assert!(cond.target_block == discovered_loop.header);
                            let op = if cond.jump_if_true {
                                BinaryOperator::NotEquals
                            } else {
                                BinaryOperator::Equals
                            };
                            statements.push(HlrStatement::DoWhile(
                                loop_body,
                                HlrExpression::BinaryOp {
                                    op,
                                    left: Box::new(self.expr_to_hlr(
                                        &cond.condition_operand,
                                        TypeVarPath::if_cond(
                                            func.function_id(),
                                            cond.instruction_id,
                                        ),
                                    )),
                                    right: Box::new(HlrExpression::Constant(0, Type::Int)),
                                    result_type: Type::Bool,
                                },
                            ));
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
                panic!("Error translating statements: {}", e);
            }
            if let Some(in_loop) = context.in_loop {
                if current == in_loop.jump_back {
                    // done processing the loop body. Jump back is handled by the caller.
                    break;
                }
            }
            match &block.ssa().next {
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
                    panic!("Unknown next kind for block {}", current);
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
            .unwrap_or_else(|| panic!("Could not find cluster for variable {:?}", var));
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
                .symbol_renaming
                .get_function_name(function_id)
                .cloned()
                .unwrap_or_else(|| format!("{}", function_id));
            return HlrExpression::StaticFunctionReference(name);
        }
        if let Some((var, _)) = self.globals.get(&addr) {
            return HlrExpression::Variable(var.clone());
        }
        HlrExpression::Constant(c, typ)
    }
}
