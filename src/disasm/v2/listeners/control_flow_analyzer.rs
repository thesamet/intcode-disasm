use std::collections::{HashMap, HashSet};

use itertools::Itertools;
use log::trace;
use petgraph::visit::{
    depth_first_search, Control, GraphBase, IntoNeighbors, IntoNeighborsDirected, VisitMap,
    Visitable,
};
use petgraph::Direction;

use crate::disasm::hlr::ast::{
    BinaryOperator, HlrAssignmentTarget, HlrExpression, HlrFunction, HlrProgram, HlrStatement,
    HlrVariable, Scope,
};
use crate::disasm::v2::events::ModelEventListener;
use crate::disasm::v2::native::NativeInstructionKind;
use crate::disasm::v2::ssa_form::{SsaBlock, SsaOperand, SsaOperandKind, SsaVar, SsaVarKind};
use crate::disasm::v2::type_inference::types::Type;
use crate::disasm::v2::{
    control_flow::NextKind,
    dispatching::EventCollector,
    events::{Event, VariableAnalysisComplete},
    model::{BlockId, ProgramModel},
    ssa_form::SsaFunction,
};
use crate::disasm::Error;

/// Listener that analyzes the control flow graph and recovers
/// high-level control flow structures like loops, if-else statements, etc.
/// It listens for the VariableAnalysisComplete event as a signal that
/// prerequisite analyses (CFG, SSA, Types, Variables) are done.
#[derive(Debug, Default)]
pub struct ControlFlowStructureRecoveryListener {
    /// The recovered high-level control flow structures (HLR program)
    hlr_program: Option<HlrProgram>,
}

impl ControlFlowStructureRecoveryListener {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ModelEventListener for ControlFlowStructureRecoveryListener {
    fn on_variable_analysis_complete(
        &mut self,
        model: &mut ProgramModel,
        _event: VariableAnalysisComplete,
        _sender: &mut EventCollector<Event>,
    ) -> Result<(), Error> {
        let program = ControlFlowStructureAnalyzer::new(model).recover_structures()?;

        // Store the recovered program
        self.hlr_program = Some(program.clone());
        model.set_hlr_program(program);

        // Publish an event to signal that structure recovery is complete
        _sender.publish(crate::disasm::v2::events::StructureRecoveryComplete {});
        Ok(())
    }
}

struct ControlFlowStructureAnalyzer<'a> {
    model: &'a ProgramModel,
}

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

impl GraphBase for SsaFunction {
    #[doc = r" edge identifier"]
    type EdgeId = ();

    #[doc = r" node identifier"]
    type NodeId = BlockId;
}

impl IntoNeighbors for &SsaFunction {
    type Neighbors = std::vec::IntoIter<BlockId>;

    fn neighbors(self, a: Self::NodeId) -> Self::Neighbors {
        self.blocks[&a].native_next.successors().into_iter()
    }
}

impl IntoNeighborsDirected for &SsaFunction {
    type NeighborsDirected = std::vec::IntoIter<BlockId>;

    fn neighbors_directed(self, n: Self::NodeId, d: Direction) -> Self::NeighborsDirected {
        match d {
            Direction::Outgoing => self.blocks[&n].native_next.successors().into_iter(),
            Direction::Incoming => self.blocks[&n]
                .native_predecessors
                .iter()
                .map(|pred| pred.source_block_id())
                .collect_vec()
                .into_iter(),
        }
    }
}

pub struct SsaVisitMap(HashSet<BlockId>);

impl VisitMap<BlockId> for SsaVisitMap {
    fn visit(&mut self, a: BlockId) -> bool {
        self.0.insert(a)
    }

    fn is_visited(&self, a: &BlockId) -> bool {
        self.0.contains(a)
    }

    fn unvisit(&mut self, a: BlockId) -> bool {
        self.0.remove(&a)
    }
}

impl Visitable for &SsaFunction {
    #[doc = r" The associated map type"]
    type Map = SsaVisitMap;

    #[doc = r" Create a new visitor map"]
    fn visit_map(&self) -> Self::Map {
        SsaVisitMap(HashSet::new())
    }

    #[doc = r" Reset the visitor map (and resize to new size of graph if needed)"]
    fn reset_map(&self, map: &mut Self::Map) {
        map.0.clear();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LoopStructure {
    header: BlockId,    // loop entry point. 'continue' jumps here.
    jump_back: BlockId, // the furthest block that has a jump back to the header.
    exit: Option<BlockId>, // a block outside the loop that we possible jump to from the loop.
                        // if None, the loop is infinite. If not, 'break' jumps here.
}

impl<'a> ControlFlowStructureAnalyzer<'a> {
    fn new(model: &'a ProgramModel) -> Self {
        Self { model }
    }

    /// Recovers high-level control flow structures for the entire program.
    fn recover_structures(&self) -> Result<HlrProgram, Error> {
        let ssa_result = self.model.get_ssa_result().ok_or_else(|| {
            Error::AnalysisFailure("SSA result not found for control flow recovery".to_string())
        })?;

        let mut hlr_functions = Vec::new();
        let globals = Vec::new();

        // Process each function in the program
        for ssa_func in ssa_result.functions.values() {
            // Get parameter types from function call analysis (if available)
            let hlr_function = self.analyze_function(ssa_func)?;

            hlr_functions.push(hlr_function);
        }

        // Create and store the HlrProgram
        let hlr_program = HlrProgram {
            functions: hlr_functions,
            globals,
        };

        Ok(hlr_program)
    }

    fn analyze_function(&self, ssa_func: &SsaFunction) -> Result<HlrFunction, Error> {
        let func = self.model.get_function(ssa_func.original_id);

        let doms = petgraph::algo::dominators::simple_fast(&ssa_func, func.entry_block);
        let post_doms: Option<petgraph::algo::dominators::Dominators<BlockId>> =
            func.return_block.map(|return_point| {
                let rev = petgraph::visit::Reversed(ssa_func);

                petgraph::algo::dominators::simple_fast(&rev, return_point)
            });

        // Maps loop headers to the loop jump back
        let mut loops: HashMap<BlockId, LoopStructure> = HashMap::new();

        // Maps if blocks to the merge point
        let mut ifs: HashMap<BlockId, BlockId> = HashMap::new();
        for node in ssa_func.blocks.keys() {
            let mut has_back_edge = false;
            for potential_header in ssa_func.neighbors(*node) {
                if doms.dominators(*node).unwrap().contains(&potential_header) {
                    has_back_edge = true;
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
            if ssa_func.neighbors(*node).count() > 1 && !has_back_edge {
                let merge_point = post_doms
                    .as_ref()
                    .unwrap()
                    .immediate_dominator(*node)
                    .unwrap_or_else(|| panic!("No immediate dominator for node {}", node));
                ifs.insert(*node, merge_point);
                trace!(
                    "Function_i={} has if: {} -> {}",
                    func.function_id,
                    node,
                    merge_point
                );
            }
        }
        for (_, lp) in loops.iter_mut() {
            let mut jump_outs = HashSet::new();
            depth_first_search(ssa_func, Some(lp.header), |u| match u {
                petgraph::visit::DfsEvent::Discover(v, _) if v > lp.jump_back => {
                    Control::<()>::Prune
                }
                _ => Control::Continue,
            });
            let mut dfs = petgraph::visit::Dfs::new(&ssa_func, lp.header);
            while let Some(u) = dfs.next(&ssa_func) {
                for v in ssa_func.neighbors(u) {
                    if v > lp.jump_back {
                        jump_outs.insert(v);
                    }
                }
            }
            assert!(jump_outs.len() <= 2,);
            if jump_outs.len() == 2 {
                let function = self.model.get_function(ssa_func.original_id);
                assert!(jump_outs.remove(&function.return_block.unwrap()));
            }
            lp.exit = jump_outs.iter().exactly_one().ok().cloned();
            trace!("Function_i={} has loop: {:?}", func.function_id, lp);
        }
        let args = self
            .model
            .get_type_inference_result()
            .unwrap()
            .function_signatures[&func.function_id]
            .0
            .iter()
            .map(|(_, t, _)| self.hlr_var(t))
            .collect_vec();

        let mut context = FunctionAnalysisContext::new(loops, ifs);

        // Add args to the context so they do not get "let" statements on
        // first write.
        for arg in &args {
            context.vars.insert(arg.clone());
        }
        let mut stmts = self.analyze_block(ssa_func, &mut context, func.entry_block, None);
        stmts.extend(self.maybe_return_statement(ssa_func, true));
        let return_type = self
            .model
            .get_type_inference_result()
            .unwrap()
            .function_signatures[&func.function_id]
            .1
            .iter()
            .map(|(_, t, _)| self.hlr_var(t))
            .collect_vec();

        let hlr = HlrFunction {
            original_id: func.function_id,
            name: format!("{}", func.function_id), // Generate a placeholder name
            args,
            return_type,
            body: stmts,
        };
        Ok(hlr)
    }

    fn analyze_block(
        &self,
        ssa_func: &SsaFunction,
        context: &mut FunctionAnalysisContext,
        start: BlockId,
        end: Option<BlockId>,
    ) -> Vec<HlrStatement> {
        let mut current = start;
        let mut statements = vec![];
        let func = self.model.get_function(ssa_func.original_id);
        while Some(current) != end {
            let block = &ssa_func.blocks[&current];
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
                        let loop_body = self.analyze_block(ssa_func, context, current, None);
                        if let NextKind::Condition(cond) =
                            &ssa_func.blocks[&discovered_loop.jump_back].native_next
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
                                    left: Box::new(self.op_expr(&cond.condition_operand)),
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
            if let Err(e) = self.translate_statements(ssa_func, context, block, &mut statements) {
                panic!("Error translating statements: {}", e);
            }
            if let Some(in_loop) = context.in_loop {
                if current == in_loop.jump_back {
                    // done processing the loop body. Jump back is handled by the caller.
                    break;
                }
            }
            match &block.native_next {
                NextKind::Follows(next) => {
                    current = *next;
                }
                NextKind::Goto(addr) => {
                    match (context.in_loop, context.in_if.last(), func.return_block) {
                        (Some(in_loop), _, _) if *addr == in_loop.header => {
                            statements.push(HlrStatement::Continue);
                            break;
                        }
                        (Some(in_loop), _, _) if Some(*addr) == in_loop.exit => {
                            statements.push(HlrStatement::Break);
                            break;
                        }
                        (_, _, Some(return_block)) if *addr == return_block => {
                            statements.extend(self.maybe_return_statement(ssa_func, false));
                            break;
                        }
                        (_, Some((_, merge_point)), _) if addr == merge_point => {
                            break;
                        }
                        _ => panic!(
                            "Goto unknown from block {} to {}. Return_block: {:?}",
                            current, addr, func.return_block
                        ),
                    }
                }
                NextKind::FunctionCall(call) => {
                    let csi = self
                        .model
                        .get_function_call_analysis()
                        .unwrap()
                        .call_site_info
                        .get(&call.calling_block)
                        .unwrap();
                    let args = csi
                        .argument_writes
                        .iter()
                        .sorted()
                        .map(|(_, v)| self.var_expr(v))
                        .collect_vec();
                    let fcall = HlrExpression::FunctionCall(
                        Box::new(self.op_expr(&call.function_addr)),
                        args,
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
                NextKind::Condition(cond) => {
                    let op = if cond.jump_if_true {
                        BinaryOperator::NotEquals
                    } else {
                        BinaryOperator::Equals
                    };
                    let cond_expr = HlrExpression::BinaryOp {
                        op,
                        left: Box::new(self.op_expr(&cond.condition_operand)),
                        right: Box::new(HlrExpression::Constant(0, Type::Int)),
                        result_type: Type::Bool,
                    };
                    if let Some(in_loop) = context.in_loop {
                        if current != in_loop.jump_back {
                            // since it is not the final jump back in the block (caller handled that),
                            // then only the target can be a jump to the header or exit.
                            if cond.target_block == in_loop.header {
                                statements.push(HlrStatement::If(
                                    cond_expr,
                                    vec![HlrStatement::Continue],
                                    vec![],
                                ));
                                current = cond.follows_block;
                                continue;
                            } else if Some(cond.target_block) == in_loop.exit {
                                statements.push(HlrStatement::If(
                                    cond_expr,
                                    vec![HlrStatement::Break],
                                    vec![],
                                ));
                                current = cond.follows_block;
                                continue;
                            }
                        }
                    }
                    if Some(cond.target_block) == func.return_block {
                        statements.push(HlrStatement::If(
                            cond_expr,
                            vec![HlrStatement::Return(vec![])],
                            vec![],
                        ));
                        self.maybe_return_statement(ssa_func, false);
                        current = cond.follows_block;
                        continue;
                    }
                    if let Some(merge_point) = context.ifs.get(&current).cloned() {
                        context.in_if.push((current, merge_point));
                        let true_branch = self.analyze_block(
                            ssa_func,
                            context,
                            cond.target_block,
                            Some(merge_point),
                        );
                        let false_branch = self.analyze_block(
                            ssa_func,
                            context,
                            cond.follows_block,
                            Some(merge_point),
                        );
                        context.in_if.pop();
                        statements.push(HlrStatement::If(cond_expr, true_branch, false_branch));
                        current = merge_point;
                        continue;
                    }
                    unreachable!(
                        "Goto unknown from block {} to {}",
                        current, cond.target_block
                    );
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

    fn var_expr(&self, var: &SsaVar) -> HlrExpression {
        HlrExpression::Variable(self.hlr_var(var))
    }

    fn hlr_var(&self, var: &SsaVar) -> HlrVariable {
        let vars = self.model.get_variable_merger_result().unwrap();
        let cluster_id = vars
            .variable_to_cluster
            .get(var)
            .unwrap_or_else(|| panic!("Could not find cluster for variable {}", var));
        let cluster = &vars.clusters[cluster_id];
        let name = cluster.cluster_name.clone();
        let typ = self.var_type(var);
        HlrVariable {
            name,
            type_info: typ,
            scope: match var.kind {
                SsaVarKind::Memory(_) => Scope::Global,
                _ => Scope::Local,
            },
        }
    }

    fn op_expr(&self, op: &SsaOperand) -> HlrExpression {
        match op.kind {
            SsaOperandKind::Constant(val) => {
                match self
                    .model
                    .get_type_inference_result()
                    .unwrap()
                    .get_type_for_ssaoperand(op)
                    .unwrap_or(&Type::Int)
                {
                    Type::Int => HlrExpression::Constant(val, Type::Int),
                    Type::Bool => HlrExpression::Constant(val, Type::Bool),
                    Type::Char => HlrExpression::Constant(val, Type::Char),
                    Type::Function { .. } => {
                        HlrExpression::StaticFunctionReference(format!("fu{}", val.to_string()))
                    }
                    _ => HlrExpression::Constant(val, Type::Int),
                }
            }
            SsaOperandKind::Variable(var) => self.var_expr(&var),
            SsaOperandKind::Deref(var) => HlrExpression::Deref(Box::new(self.var_expr(&var))),
        }
    }

    fn var_type(&self, var: &SsaVar) -> Type {
        let vars = self.model.get_variable_merger_result().unwrap();
        let cluster_id = vars.variable_to_cluster[var];
        let cluster = &vars.clusters[&cluster_id];
        cluster.inferred_type.clone()
    }

    fn translate_statements(
        &self,
        _ssa_func: &SsaFunction,
        context: &mut FunctionAnalysisContext, // Mark context as potentially unused for now
        block: &SsaBlock,
        statements: &mut Vec<HlrStatement>,
    ) -> Result<(), Error> {
        // Closure to create an HLR assignment target for a variable

        for instr in &block.native_instructions {
            let stmt = match &instr.kind {
                NativeInstructionKind::Add(a, b, c) => {
                    let result_var = c.as_variable().ok_or_else(|| {
                        Error::AnalysisFailure("Add instruction expects variable target".to_string())
                    })?;
                    self.assign_or_def(context,result_var,
                        HlrExpression::BinaryOp {
                            op: BinaryOperator::Add,
                            left: Box::new(self.op_expr(a)),
                            right: Box::new(self.op_expr(b)),
                            result_type: self.var_type(result_var), // Use var_type of the result var
                        },
                    )
                }
                NativeInstructionKind::Mul(a, b, c) => {
                    let result_var = c.as_variable().ok_or_else(|| {
                        Error::AnalysisFailure("Mul instruction expects variable target".to_string())
                    })?;
                    self.assign_or_def(context, result_var, HlrExpression::BinaryOp {
                        op: BinaryOperator::Mul,
                        left: Box::new(self.op_expr(a)),
                        right: Box::new(self.op_expr(b)),
                        result_type: self.var_type(result_var), // Use var_type of the result var
                    })
                }
                NativeInstructionKind::Input(a) => {
                    let result_var = a.as_variable().ok_or_else(|| {
                        Error::AnalysisFailure("Input instruction expects variable target".to_string())
                    })?;
                    self.assign_or_def(context, result_var, HlrExpression::Input())
                }
                NativeInstructionKind::Output(a) => HlrStatement::Output(self.op_expr(a)),
                NativeInstructionKind::LessThan(a, b, c) => {
                    let result_var = c.as_variable().ok_or_else(|| Error::AnalysisFailure(
                        "LessThan instruction expects variable target".to_string(),
                    ))?;
                    self.assign_or_def(context,result_var, HlrExpression::BinaryOp {
                        op: BinaryOperator::LessThan,
                        left: Box::new(self.op_expr(a)),
                        right: Box::new(self.op_expr(b)),
                        result_type: Type::Bool, // Comparison result is Bool
                    })
                }
                NativeInstructionKind::Equals(a, b, c) => {
                    let result_var = c.as_variable().ok_or_else(|| {
                        Error::AnalysisFailure("Equals instruction expects variable target".to_string())
                    })?;
                    self.assign_or_def(context,result_var, HlrExpression::BinaryOp {
                        op: BinaryOperator::Equals,
                        left: Box::new(self.op_expr(a)),
                        right: Box::new(self.op_expr(b)),
                        result_type: Type::Bool, // Comparison result is Bool
                    })
                }
                NativeInstructionKind::Assign(dst, src) => {
                    let src = self.op_expr(src);
                    match dst.kind {
                        SsaOperandKind::Deref(var) =>
                                HlrStatement::Assignment(
                                    HlrAssignmentTarget::Deref(self.var_expr(&var)),
                                    src,
                                ),
                        SsaOperandKind::Constant(_) => {
                            return Err(Error::AnalysisFailure(
                                "Cannot assign into a constant".to_string(),
                            ))
                        }
                        SsaOperandKind::Variable(target_ssa_var) => {
                            if target_ssa_var.get_relative_memory() == Some(0) {
                                // We skip adjustments to R, not relevant in this level of abstraction
                                continue;
                            }
                            let hlr_target_var = self.hlr_var(&target_ssa_var);
                            if let HlrExpression::Variable(src_var) = &src {
                                if *src_var == hlr_target_var {
                                    continue;
                                }
                            }
                            self.assign_or_def(context, &target_ssa_var, src)
                        }
                    }
                },
                NativeInstructionKind::Data(_) => {
                   // Data instructions are not executable code, skip.
                   continue;
                }
                 // Control flow instructions are handled by the block's `next` field analysis, skip here.
                NativeInstructionKind::JumpIfTrue(_, _)
                | NativeInstructionKind::JumpIfFalse(_, _)
                | NativeInstructionKind::AdjustRelativeBase(_) // This might become an assignment, needs careful handling
                | NativeInstructionKind::Goto(_)
                | NativeInstructionKind::Halt => {
                    continue; // Handled by block terminators or structure analysis
                }
            };
            statements.push(stmt);
        }
        Ok(())
    }

    // Returns some return statement if it's an early return or there are return values.
    fn maybe_return_statement(&self, func: &SsaFunction, is_end: bool) -> Option<HlrStatement> {
        let rets = self
            .model
            .get_type_inference_result()
            .unwrap()
            .function_signatures[&func.original_id]
            .1
            .iter()
            .map(|(_, t, _)| self.var_expr(t))
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
        var: &SsaVar,
        expr: HlrExpression,
    ) -> HlrStatement {
        let hlr = self.hlr_var(var);
        if context.vars.contains(&hlr) {
            HlrStatement::Assignment(HlrAssignmentTarget::Variable(hlr), expr)
        } else {
            context.vars.insert(hlr.clone());
            HlrStatement::VarDef(vec![hlr], expr)
        }
    }
}
