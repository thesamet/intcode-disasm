use std::collections::{HashMap, HashSet};

use itertools::Itertools;
use petgraph::visit::{GraphBase, IntoNeighbors, IntoNeighborsDirected, VisitMap, Visitable};
use petgraph::Direction;

use crate::disasm::hlr::ast::{
    pretty_print_program, BinaryOperator, HlrAssignmentTarget, HlrExpression, HlrFunction,
    HlrProgram, HlrStatement, HlrVariable,
};
use crate::disasm::v2::events::ModelEventListener;
use crate::disasm::v2::instructions::InstructionKind;
use crate::disasm::v2::ssa_form::{SsaBlock, SsaOperand, SsaOperandKind, SsaVar};
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

    /// Gets the recovered high-level representation of the program, if available
    pub fn get_hlr_program(&self) -> Option<&HlrProgram> {
        self.hlr_program.as_ref()
    }
}

impl ModelEventListener for ControlFlowStructureRecoveryListener {
    fn on_variable_analysis_complete(
        &mut self,
        model: &mut ProgramModel,
        _event: VariableAnalysisComplete,
        _sender: &mut EventCollector<Event>,
    ) -> Result<(), Error> {
        println!(
            "Received VariableAnalysisComplete event. Starting control flow structure recovery..."
        );

        let program = ControlFlowStructureAnalyzer::new(model).recover_structures()?;
        println!("{}", pretty_print_program(&program));

        // Store the recovered program
        self.hlr_program = Some(program.clone());
        model.set_hlr_program(program);

        println!("Control flow structure recovery finished.");
        Ok(())
    }
}

struct ControlFlowStructureAnalyzer<'a> {
    model: &'a ProgramModel,
}

#[derive(Debug, Clone)]
struct FunctionAnalysisContext {
    loops: HashMap<BlockId, BlockId>,
    ifs: HashMap<BlockId, BlockId>,
    in_loop: Option<(BlockId, BlockId)>,
    in_if: Option<(BlockId, BlockId)>,
}

impl FunctionAnalysisContext {
    fn new(loops: HashMap<BlockId, BlockId>, ifs: HashMap<BlockId, BlockId>) -> Self {
        Self {
            loops,
            ifs,
            in_loop: None,
            in_if: None,
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
        self.blocks[&a].next.successors().into_iter()
    }
}

impl IntoNeighborsDirected for &SsaFunction {
    type NeighborsDirected = std::vec::IntoIter<BlockId>;

    fn neighbors_directed(self, n: Self::NodeId, d: Direction) -> Self::NeighborsDirected {
        match d {
            Direction::Outgoing => self.blocks[&n].next.successors().into_iter(),
            Direction::Incoming => self.blocks[&n]
                .predecessors
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
    fn visit_map(self: &Self) -> Self::Map {
        SsaVisitMap(HashSet::new())
    }

    #[doc = r" Reset the visitor map (and resize to new size of graph if needed)"]
    fn reset_map(self: &Self, map: &mut Self::Map) {
        map.0.clear();
    }
}

impl<'a> ControlFlowStructureAnalyzer<'a> {
    fn new(model: &'a ProgramModel) -> Self {
        Self { model }
    }

    /// Recovers high-level control flow structures for the entire program.
    fn recover_structures(&self) -> Result<HlrProgram, Error> {
        let ssa_result = self.model.get_ssa_result().ok_or_else(|| {
            Error::AnalysisError("SSA result not found for control flow recovery".to_string())
        })?;

        let mut hlr_functions = Vec::new();
        let globals = Vec::new();

        // Process each function in the program
        for (_, ssa_func) in &ssa_result.functions {
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
                let post_doms = petgraph::algo::dominators::simple_fast(&rev, return_point);
                post_doms
            });

        // Maps loop headers to the loop jump back
        let mut loops: HashMap<BlockId, BlockId> = HashMap::new();

        // Maps if blocks to the merge point
        let mut ifs: HashMap<BlockId, BlockId> = HashMap::new();
        for node in ssa_func.blocks.keys() {
            let mut has_back_edge = false;
            for potential_header in ssa_func.neighbors(*node) {
                if doms.dominators(*node).unwrap().contains(&potential_header) {
                    has_back_edge = true;
                    let current_loop = loops.entry(potential_header).or_insert(*node);
                    if node > current_loop {
                        *current_loop = *node;
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
            }
        }
        let context = FunctionAnalysisContext::new(loops, ifs);
        let stmts = self.analyze_block(ssa_func, &context, func.entry_block, None);
        let hlr = HlrFunction {
            original_id: func.function_id,
            name: format!("{}", func.function_id), // Generate a placeholder name
            args: vec![],
            return_type: vec![],
            body: stmts,
        };
        Ok(hlr)
    }

    fn analyze_block(
        &self,
        ssa_func: &SsaFunction,
        context: &FunctionAnalysisContext,
        start: BlockId,
        end: Option<BlockId>,
    ) -> Vec<HlrStatement> {
        let mut current = start;
        let mut statements = vec![];
        while Some(current) != end {
            let block = ssa_func.blocks.get(&current).unwrap();
            let _func = self.model.get_function(ssa_func.original_id);
            if let Some(loop_end) = context.loops.get(&current) {
                match context.in_loop {
                    // We are already processing a loop. Check for unsupported nesting.
                    Some(existing_loop) => {
                        if existing_loop != (current, *loop_end) {
                            // Found a different loop header while already processing `existing_loop`.
                            panic!("Nested loops not supported");
                        }
                    }
                    // Not currently processing a loop, so start processing this one.
                    None => {
                        let mut inner_context = context.clone();
                        inner_context.in_loop = Some((current, *loop_end));
                        let loop_body =
                            self.analyze_block(ssa_func, &inner_context, current, Some(*loop_end));
                        statements.push(HlrStatement::Loop(loop_body));
                        return statements;
                    }
                }
            }
            if let Err(e) = self.translate_statements(ssa_func, context, block, &mut statements) {
                panic!("Error translating statements: {}", e);
            }
            match &block.next {
                NextKind::Follows(next) => {
                    current = *next;
                }
                NextKind::Goto(addr) => {
                    /* if Some(*addr) == func.return_block {
                        statements.push(HlrStatement::Return(vec![]));
                        break;
                    } else */
                    if let Some((start, _)) = context.in_loop {
                        if *addr == start {
                            statements.push(HlrStatement::Continue);
                            break;
                        } else {
                            statements.push(HlrStatement::Break);
                            break;
                        }
                    } else if let Some((_, merge_point)) = context.in_if {
                        if *addr == merge_point {
                            break;
                        }
                    }
                    panic!("Goto unknown from block {} to {}", current, addr);
                }
                NextKind::FunctionCall(call) => {
                    statements.push(HlrStatement::Assignment(
                        HlrAssignmentTarget::Ignored,
                        HlrExpression::FunctionCall(Box::new(HlrExpression::Variable(
                            HlrVariable {
                                name: call.function_addr.to_string(),
                                type_info: Type::Bool,
                            },
                        ))),
                    ));
                    current = call.return_block;
                }
                NextKind::Condition(cond) => {
                    println!(
                        "Found cond block {} with target {} and follow {}",
                        current, cond.target_block, cond.follows_block
                    );
                    if let Some(merge_point) = context.ifs.get(&current) {
                        let mut new_context = context.clone();
                        new_context.in_if = Some((current, *merge_point));
                        let true_branch = self.analyze_block(
                            ssa_func,
                            &new_context,
                            cond.target_block,
                            Some(*merge_point),
                        );
                        let false_branch = self.analyze_block(
                            ssa_func,
                            &new_context,
                            cond.follows_block,
                            Some(*merge_point),
                        );
                        let op = if cond.jump_if_true {
                            BinaryOperator::NotEquals
                        } else {
                            BinaryOperator::Equals
                        };
                        statements.push(HlrStatement::If(
                            HlrExpression::BinaryOp {
                                op,
                                left: Box::new(self.op_expr(&cond.condition_operand)),
                                right: Box::new(HlrExpression::Constant(0, Type::Int)),
                                result_type: Type::Bool,
                            },
                            true_branch,
                            false_branch,
                        ));
                        current = *merge_point;
                        continue;
                    }
                    if let Some((start, _)) = context.in_loop {
                        if cond.target_block == start {
                            statements.push(HlrStatement::Continue);
                            break;
                        } else {
                            statements.push(HlrStatement::Break);
                            break;
                        }
                    } else {
                        panic!(
                            "Cond Goto unknown from block {} to {} {:?}",
                            current,
                            cond.target_block,
                            context.ifs.get(&current)
                        );
                    }
                }
                NextKind::Return => {
                    statements.push(HlrStatement::Return(vec![]));
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
        let cluster_id = vars.variable_to_cluster[&var];
        let cluster = &vars.clusters[&cluster_id];
        let name = cluster.cluster_name.clone();
        let typ = self.var_type(var);
        HlrVariable {
            name,
            type_info: typ,
        }
    }

    fn op_expr(&self, op: &SsaOperand) -> HlrExpression {
        match op.kind {
            SsaOperandKind::Constant(val) => HlrExpression::Constant(val, Type::Int),
            SsaOperandKind::Variable(var) => self.var_expr(&var),
            SsaOperandKind::Deref(var) => HlrExpression::Deref(Box::new(self.var_expr(&var))),
        }
    }

    fn var_type(&self, var: &SsaVar) -> Type {
        let vars = self.model.get_variable_merger_result().unwrap();
        let cluster_id = vars.variable_to_cluster[&var];
        let cluster = &vars.clusters[&cluster_id];
        cluster.inferred_type.clone()
    }

    fn op_type(&self, op: &SsaOperand) -> Type {
        match op.kind {
            SsaOperandKind::Constant(_) => Type::Int, // Assuming Int
            SsaOperandKind::Variable(var) => self.var_type(&var),
            SsaOperandKind::Deref(var) => match self.var_type(&var) {
                Type::Pointer(pointee) => *pointee,
                _ => unreachable!(),
            },
        }
    }

    fn translate_statements(
        &self,
        _ssa_func: &SsaFunction,
        _context: &FunctionAnalysisContext, // Mark context as potentially unused for now
        block: &SsaBlock,
        statements: &mut Vec<HlrStatement>,
    ) -> Result<(), Error> {
        // Closure to create an HLR assignment target for a variable
        let hlr_assignment = |var: &SsaVar| HlrAssignmentTarget::Variable(self.hlr_var(var));

        for instr in &block.instructions {
            let stmt = match &instr.kind {
                InstructionKind::Add(a, b, c) => {
                    let result_var = c.as_variable().ok_or_else(|| {
                        Error::AnalysisError("Add instruction expects variable target".to_string())
                    })?;
                    HlrStatement::Assignment(
                        hlr_assignment(result_var),
                        HlrExpression::BinaryOp {
                            op: BinaryOperator::Add,
                            left: Box::new(self.op_expr(a)),
                            right: Box::new(self.op_expr(b)),
                            result_type: self.var_type(result_var), // Use var_type of the result var
                        },
                    )
                }
                InstructionKind::Mul(a, b, c) => {
                    let result_var = c.as_variable().ok_or_else(|| {
                        Error::AnalysisError("Mul instruction expects variable target".to_string())
                    })?;
                    HlrStatement::Assignment(
                        hlr_assignment(result_var),
                        HlrExpression::BinaryOp {
                            op: BinaryOperator::Mul,
                            left: Box::new(self.op_expr(a)),
                            right: Box::new(self.op_expr(b)),
                            result_type: self.var_type(result_var), // Use var_type of the result var
                        },
                    )
                }
                InstructionKind::Input(a) => {
                    let result_var = a.as_variable().ok_or_else(|| {
                        Error::AnalysisError("Input instruction expects variable target".to_string())
                    })?;
                    HlrStatement::Assignment(hlr_assignment(result_var), HlrExpression::Input())
                }
                InstructionKind::Output(a) => HlrStatement::Output(self.op_expr(a)),
                InstructionKind::LessThan(a, b, c) => {
                    let result_var = c.as_variable().ok_or_else(|| Error::AnalysisError(
                        "LessThan instruction expects variable target".to_string(),
                    ))?;
                    HlrStatement::Assignment(
                        hlr_assignment(result_var),
                        HlrExpression::BinaryOp {
                            op: BinaryOperator::LessThan,
                            left: Box::new(self.op_expr(a)),
                            right: Box::new(self.op_expr(b)),
                            result_type: Type::Bool, // Comparison result is Bool
                        },
                    )
                }
                InstructionKind::Equals(a, b, c) => {
                    let result_var = c.as_variable().ok_or_else(|| {
                        Error::AnalysisError("Equals instruction expects variable target".to_string())
                    })?;
                    HlrStatement::Assignment(
                        hlr_assignment(result_var),
                        HlrExpression::BinaryOp {
                            op: BinaryOperator::Equals,
                            left: Box::new(self.op_expr(a)),
                            right: Box::new(self.op_expr(b)),
                            result_type: Type::Bool, // Comparison result is Bool
                        },
                    )
                }
                InstructionKind::Assign(dst, src) => {
                    let src = self.op_expr(src);
                    let target = match dst.kind {
                        SsaOperandKind::Deref(var) => HlrAssignmentTarget::Deref(self.var_expr(&var)),
                        SsaOperandKind::Constant(_) => {
                            return Err(Error::AnalysisError(
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
                            HlrAssignmentTarget::Variable(hlr_target_var)
                        }
                    };
                    HlrStatement::Assignment(target, src)
                }
                InstructionKind::Data(_) => {
                   // Data instructions are not executable code, skip.
                   continue;
                }
                 // Control flow instructions are handled by the block's `next` field analysis, skip here.
                InstructionKind::JumpIfTrue(_, _)
                | InstructionKind::JumpIfFalse(_, _)
                | InstructionKind::AdjustRelativeBase(_) // This might become an assignment, needs careful handling
                | InstructionKind::Goto(_)
                | InstructionKind::Halt => {
                    continue; // Handled by block terminators or structure analysis
                }
            };
            statements.push(stmt);
        }
        Ok(())
    }
}
