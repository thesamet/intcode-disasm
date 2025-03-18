use std::collections::HashMap;

use log::trace;
use pathfinding::prelude::dfs;

use super::{
    low_ir::{Arg, Span},
    mid_ir::MidIR,
};

#[derive(Debug)]
pub enum ControlFlowError {
    LoopNoBackJump,
    WhileNoConditionalJump,
    WhileJumpBackDoesNotMatchJumpIf,
    IfNoConditionalJump,
    NoMatch,
    UnexpectedGoto,
}

#[derive(Debug, Clone)]
pub enum FlowNodeKind {
    NonBranching(Vec<MidIR>),
    JumpIf {
        value: Arg,
        equal_to: bool,
        target: usize,
    },
    Goto(usize),
    Return,
}

impl FlowNodeKind {
    fn is_non_branching(&self) -> bool {
        matches!(self, FlowNodeKind::NonBranching(_))
    }

    fn is_jump_if(&self) -> bool {
        matches!(self, FlowNodeKind::JumpIf { .. })
    }

    fn is_goto(&self) -> bool {
        matches!(self, FlowNodeKind::Goto(_))
    }

    fn jump_address(&self) -> Option<usize> {
        match self {
            FlowNodeKind::JumpIf { target, .. } | FlowNodeKind::Goto(target) => Some(*target),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FlowNode {
    pub kind: FlowNodeKind,
    pub span: Span,
}

impl FlowNode {
    pub fn non_branching(span: Span, instructions: Vec<MidIR>) -> Self {
        FlowNode {
            kind: FlowNodeKind::NonBranching(instructions),
            span,
        }
    }

    pub fn jump_if(span: Span, value: Arg, equal_to: bool, target: usize) -> Self {
        FlowNode {
            kind: FlowNodeKind::JumpIf {
                value,
                equal_to,
                target,
            },
            span,
        }
    }

    pub fn goto(span: Span, target: usize) -> Self {
        FlowNode {
            kind: FlowNodeKind::Goto(target),
            span,
        }
    }

    pub fn new_return(span: Span) -> Self {
        FlowNode {
            kind: FlowNodeKind::Return,
            span,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FlowGraph {
    nodes: HashMap<usize, FlowNode>,
    inbounds: HashMap<usize, Vec<usize>>,
}

impl FlowGraph {
    fn next(&self, node: &FlowNode) -> Option<&FlowNode> {
        if let FlowNodeKind::Return = node.kind {
            None
        } else {
            self.nodes.get(&node.span.end)
        }
    }

    fn inbound_by_jump(&self, node: &FlowNode, region: Span) -> Vec<&FlowNode> {
        self.inbounds
            .get(&node.span.start)
            .unwrap_or(&vec![])
            .iter()
            .filter(|&&a| region.contains_address(a))
            .map(|&i| self.nodes.get(&i).unwrap())
            .collect()
    }

    pub fn build_from(nodes: &[FlowNode]) -> Self {
        let mut graph = FlowGraph {
            nodes: HashMap::new(),
            inbounds: HashMap::new(),
        };
        for node in nodes {
            graph.nodes.insert(node.span.start, node.clone());
            match node.kind {
                FlowNodeKind::JumpIf { target, .. } | FlowNodeKind::Goto(target) => {
                    graph
                        .inbounds
                        .entry(target)
                        .or_default()
                        .push(node.span.start);
                }
                _ => {}
            }
        }
        assert!(
            graph.inbounds.keys().all(|k| graph.nodes.contains_key(k)),
            "Jump to an unmarked address {}",
            graph
                .inbounds
                .keys()
                .find(|k| !graph.nodes.contains_key(k))
                .unwrap()
        );
        /*
                assert!(nodes
                    .iter()
                    .filter(|n| matches!(n.kind, FlowNodeKind::Return))
                    .all(|n| graph.next(n).is_some()));
        */
        graph
    }
}

impl FlowHigh {
    fn new(flows: Vec<FlowHigh>) -> Self {
        FlowHigh::Composite(flows)
    }
}

#[derive(PartialEq, Clone, Copy)]
pub struct LoopId(pub usize);

impl std::fmt::Debug for LoopId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum FlowHigh {
    NonBranching {
        span: Span, // represents a code range without jumps.
        instructions: Vec<MidIR>,
    },
    Composite(Vec<FlowHigh>), // represents multiple non-overlapping flows that execute
    // consecutively.
    While {
        id: LoopId,
        jump_if_span: Span,
        expr: Option<Box<FlowHigh>>,
        body: Box<FlowHigh>,
    },
    DoWhile {
        id: LoopId,
        body: Box<FlowHigh>,
        jump_if_span: Span,
    },
    Loop {
        id: LoopId,
        body: Box<FlowHigh>,
    },
    If {
        jump_if_span: Span,
        then: Box<FlowHigh>,
    },
    IfElse {
        jump_if_span: Span,
        then: Box<FlowHigh>,
        els: Box<FlowHigh>,
    },
    Return,
    Break(LoopId),
    Continue(LoopId),
}

impl FlowHigh {
    pub fn non_branching(span: Span, instructions: Vec<MidIR>) -> Self {
        FlowHigh::NonBranching { span, instructions }
    }

    fn composite(flows: Vec<FlowHigh>) -> Self {
        FlowHigh::Composite(flows)
    }

    pub fn while_loop(
        loop_id: LoopId,
        expr: Option<FlowHigh>,
        body: FlowHigh,
        jump_if_span: Span,
    ) -> Self {
        FlowHigh::While {
            id: loop_id,
            expr: expr.map(Box::new),
            body: Box::new(body),
            jump_if_span,
        }
    }

    pub fn do_while_loop(id: LoopId, body: FlowHigh, jump_if_span: Span) -> Self {
        FlowHigh::DoWhile {
            id,
            body: Box::new(body),
            jump_if_span,
        }
    }

    pub fn loop_body(id: LoopId, body: FlowHigh) -> Self {
        FlowHigh::Loop {
            id,
            body: Box::new(body),
        }
    }

    pub fn conditional(jump_if_span: Span, then: FlowHigh) -> Self {
        FlowHigh::If {
            then: Box::new(then),
            jump_if_span,
        }
    }

    pub fn if_else(jump_if_span: Span, then: FlowHigh, els: FlowHigh) -> Self {
        FlowHigh::IfElse {
            then: Box::new(then),
            els: Box::new(els),
            jump_if_span,
        }
    }

    pub fn return_flow() -> Self {
        FlowHigh::Return
    }
}

pub fn parse_flow(graph: &FlowGraph, region: Span) -> Result<FlowHigh, ControlFlowError> {
    let mut parse_context = ParseContext::new();
    let node = graph.nodes.get(&region.start).unwrap();
    dfs(
        node.span.start,
        |s| {
            if *s == region.end {
                return vec![];
            }
            let node = graph.nodes.get(s).unwrap();
            match node.kind {
                FlowNodeKind::Return => {
                    parse_context.known_jumps.insert(*s, FlowHigh::Return);
                    vec![]
                }
                FlowNodeKind::NonBranching(_) => vec![node.span.end],
                FlowNodeKind::JumpIf { target, .. } => vec![target, node.span.end],
                FlowNodeKind::Goto(target) => vec![target, node.span.end],
            }
        },
        |_| false,
    );
    let (end, result) = parse_flow_inner(graph, region, &parse_context)?;
    if end.start == region.end {
        Ok(result)
    } else {
        unreachable!()
    }
}

struct ParseContext {
    known_jumps: HashMap<usize, FlowHigh>,
    current_loop_id: Option<LoopId>,
}

impl ParseContext {
    fn new() -> Self {
        ParseContext {
            known_jumps: HashMap::new(),
            current_loop_id: None,
        }
    }
    fn with_next_loop_id(&self, continue_addr: usize, break_addr: usize) -> Self {
        let next_loop_id = LoopId(self.current_loop_id.as_ref().map(|i| i.0 + 1).unwrap_or(1));
        let mut known_jumps = self.known_jumps.clone();
        known_jumps.insert(break_addr, FlowHigh::Break(next_loop_id));
        known_jumps.insert(continue_addr, FlowHigh::Continue(next_loop_id));

        ParseContext {
            known_jumps,
            current_loop_id: Some(next_loop_id),
        }
    }
}

fn parse_flow_inner(
    graph: &FlowGraph,
    region: Span,
    parse_context: &ParseContext,
) -> Result<(Span, FlowHigh), ControlFlowError> {
    trace!(
        "Parsing region {:?} {:?}",
        region,
        parse_context.known_jumps
    );
    let mut result = vec![];
    let mut region = region;
    while region.start < region.end {
        let node = graph.nodes.get(&region.start).unwrap();
        trace!("At {:?} with node={:?}", region, node.kind);
        if let FlowNode {
            span,
            kind: FlowNodeKind::NonBranching(instructions),
        } = node
        {
            if graph.inbound_by_jump(node, region).is_empty() {
                trace!("Non-branching {:?}", span);
                result.push(FlowHigh::non_branching(*span, instructions.clone()));
                region = region.with_start(node.span.end);
                continue;
            }
        }

        let (next_region, h) = parse_return(graph, region, parse_context)
            .or_else(|_| parse_goto_marker(graph, region, parse_context))
            .or_else(|_| parse_if(graph, region, parse_context))
            .or_else(|_| parse_while(graph, region, parse_context))
            .or_else(|_| parse_do_while(graph, region, parse_context))
            .or_else(|_| parse_loop(graph, region, parse_context))?;
        trace!("*** Got {:?} {:?}", region, h);
        result.push(h);
        region = next_region;
    }
    if result.len() == 1 {
        Ok((region, result.into_iter().next().unwrap()))
    } else {
        Ok((region, FlowHigh::composite(result)))
    }
}

fn parse_goto_marker(
    graph: &FlowGraph,
    region: Span,
    parse_context: &ParseContext,
) -> Result<(Span, FlowHigh), ControlFlowError> {
    let node = graph.nodes.get(&region.start).unwrap();
    let FlowNodeKind::Goto(target) = node.kind else {
        return Err(ControlFlowError::NoMatch);
    };
    if let Some(v) = parse_context.known_jumps.get(&target) {
        Ok((region.with_start(node.span.end), v.clone()))
    } else {
        Err(ControlFlowError::UnexpectedGoto)
    }
}

fn parse_return(
    graph: &FlowGraph,
    region: Span,
    _parse_context: &ParseContext,
) -> Result<(Span, FlowHigh), ControlFlowError> {
    let node = graph.nodes.get(&region.start).unwrap();
    if let FlowNodeKind::Return = node.kind {
        Ok((region.with_start(node.span.end), FlowHigh::Return))
    } else {
        Err(ControlFlowError::NoMatch)
    }
}
fn parse_loop(
    graph: &FlowGraph,
    region: Span,
    parse_context: &ParseContext,
) -> Result<(Span, FlowHigh), ControlFlowError> {
    trace!("Trying loop {:?}", region);
    let node = graph.nodes.get(&region.start).unwrap();
    let Some(max_jump_back) = graph
        .inbound_by_jump(node, region)
        .into_iter()
        .filter(|n| n.kind.is_goto() && region.contains(&n.span))
        .map(|n| n.span)
        .max_by_key(|s| s.start)
    else {
        return Err(ControlFlowError::LoopNoBackJump);
    };
    let loop_parse_context = &parse_context.with_next_loop_id(region.start, max_jump_back.end);

    let body = parse_flow_inner(
        graph,
        Span::new(region.start, max_jump_back.start),
        loop_parse_context,
    )?
    .1;

    Ok((
        region.with_start(max_jump_back.end),
        FlowHigh::loop_body(loop_parse_context.current_loop_id.unwrap(), body),
    ))
}

fn parse_while(
    graph: &FlowGraph,
    region: Span,
    parse_context: &ParseContext,
) -> Result<(Span, FlowHigh), ControlFlowError> {
    trace!("Trying while {:?}", region);
    let start_node = graph.nodes.get(&region.start).unwrap();

    let Some(max_jump_back) = graph
        .inbound_by_jump(start_node, region)
        .into_iter()
        .max_by_key(|s| s.span.start)
        .filter(|n| n.kind.is_goto() && region.contains(&n.span))
    else {
        return Err(ControlFlowError::LoopNoBackJump);
    };

    let (expr_node, cond_node) = if start_node.kind.is_jump_if() {
        (None, start_node)
    } else if start_node.kind.is_non_branching() {
        (
            Some(start_node),
            graph
                .next(start_node)
                .filter(|n| n.kind.is_jump_if())
                .ok_or(ControlFlowError::WhileNoConditionalJump)?,
        )
    } else {
        return Err(ControlFlowError::WhileNoConditionalJump);
    };
    trace!(
        "Parsing while max_jump_back at {} and expr_node at {:?} cond_node={}",
        max_jump_back.span.start,
        expr_node.map(|e| e.span.start),
        cond_node.span.start
    );

    let FlowNodeKind::JumpIf {
        value: ref _value,
        equal_to: _equal_to,
        target: end_address,
    } = cond_node.kind
    else {
        unreachable!();
    };

    if end_address != max_jump_back.span.end {
        return Err(ControlFlowError::WhileJumpBackDoesNotMatchJumpIf);
    }
    let body_span = Span::new(cond_node.span.end, max_jump_back.span.start);
    let loop_parse_context = &parse_context.with_next_loop_id(region.start, end_address);

    let expr = expr_node
        .map(|n| parse_flow_inner(graph, n.span, loop_parse_context))
        .transpose()?
        .map(|e| e.1);
    let body = parse_flow_inner(graph, body_span, loop_parse_context)?.1;
    Ok((
        region.with_start(end_address),
        FlowHigh::while_loop(
            loop_parse_context.current_loop_id.unwrap(),
            expr,
            body,
            cond_node.span,
        ),
    ))
}

fn parse_do_while(
    graph: &FlowGraph,
    region: Span,
    parse_context: &ParseContext,
) -> Result<(Span, FlowHigh), ControlFlowError> {
    trace!("Trying do-while {:?}", region);
    let start_node = graph.nodes.get(&region.start).unwrap();

    let Some(cond_node) = graph
        .inbound_by_jump(start_node, region)
        .into_iter()
        .max_by_key(|s| s.span.start)
        .filter(|n| n.kind.is_jump_if() && region.contains(&n.span))
    else {
        return Err(ControlFlowError::LoopNoBackJump);
    };

    let FlowNodeKind::JumpIf {
        value: ref _value,
        equal_to: _equal_to,
        target: start_address,
    } = cond_node.kind
    else {
        unreachable!();
    };
    assert!(start_address == region.start);
    trace!("Parsing do-while {} {}", region.start, cond_node.span.start);
    let loop_parse_context = &parse_context.with_next_loop_id(region.start, cond_node.span.end);

    let body_span = Span::new(region.start, cond_node.span.start);
    let body = parse_flow_inner(graph, body_span, loop_parse_context)?.1;
    trace!("Got body={:?}", body);
    Ok((
        region.with_start(cond_node.span.end),
        FlowHigh::do_while_loop(
            loop_parse_context.current_loop_id.unwrap(),
            body,
            cond_node.span,
        ),
    ))
}

fn parse_if(
    graph: &FlowGraph,
    region: Span,
    parse_context: &ParseContext,
) -> Result<(Span, FlowHigh), ControlFlowError> {
    trace!("Trying if {:?} {:?}", region, parse_context.known_jumps);
    let node = graph.nodes.get(&region.start).unwrap();
    let FlowNodeKind::JumpIf {
        value: ref _value,
        equal_to: _equal_to,
        target: jump_target,
    } = node.kind
    else {
        return Err(ControlFlowError::IfNoConditionalJump);
    };
    if let Some(v) = parse_context.known_jumps.get(&jump_target) {
        return Ok((
            region.with_start(node.span.end),
            FlowHigh::conditional(node.span, v.clone()),
        ));
    }
    if jump_target < node.span.start {
        return Err(ControlFlowError::IfNoConditionalJump);
    }

    // Check if there's a goto that jumps from the end of then block to after the else block
    let then_span = Span::new(node.span.end, jump_target);

    // Find if there's a goto at the end of the then branch
    let goto_node = graph.nodes.values().find(|n| {
        n.span.end == jump_target
            && n.kind.is_goto()
            && !parse_context
                .known_jumps
                .contains_key(&n.kind.jump_address().unwrap())
    });

    if let Some(goto_node) = goto_node {
        // This is an if-else structure
        let FlowNodeKind::Goto(else_end) = goto_node.kind else {
            unreachable!();
        };

        // Adjust the then_span to end at the goto
        let then_span = Span::new(node.span.end, goto_node.span.start);
        let else_span = Span::new(jump_target, else_end);
        trace!("else span {:?}", else_span);

        let then = parse_flow_inner(graph, then_span, parse_context)?.1;
        trace!("then parsed");
        let els = parse_flow_inner(graph, else_span, parse_context)?.1;
        trace!("else parsed");

        Ok((
            region.with_start(else_end),
            FlowHigh::if_else(node.span, then, els),
        ))
    } else {
        // This is a simple if structure
        trace!("then span {:?}", then_span);
        let then = parse_flow_inner(graph, then_span, parse_context)?.1;
        trace!("then parsed");
        Ok((
            region.with_start(jump_target),
            FlowHigh::conditional(node.span, then),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn build_flow_graph(flows: &[FlowNode], region: Span) -> FlowGraph {
        let mut nodes = Vec::new();
        let mut current_start = region.start;

        for node in flows.iter() {
            if current_start < node.span.start {
                // Fill the gap with NonBranching
                nodes.push(FlowNode {
                    kind: FlowNodeKind::NonBranching(vec![]),
                    span: Span::new(current_start, node.span.start),
                });
            }

            nodes.push(node.clone());

            current_start = node.span.end;
        }

        if current_start < region.end {
            // Fill the remaining gap with NonBranching
            nodes.push(FlowNode {
                kind: FlowNodeKind::NonBranching(vec![]),
                span: Span::new(current_start, region.end),
            });
        }

        FlowGraph::build_from(&nodes)
    }

    fn test_parse_flow(nodes: &[FlowNode], region: Span) -> FlowHigh {
        let graph = build_flow_graph(nodes, region);
        parse_flow(&graph, region).unwrap()
    }

    fn arg() -> Arg {
        Arg::Value(0)
    }

    fn node_non_branching(start: usize, end: usize) -> FlowNode {
        FlowNode::non_branching(Span::new(start, end), vec![])
    }

    fn flow_high_non_branching(start: usize, end: usize) -> FlowHigh {
        FlowHigh::non_branching(Span::new(start, end), vec![])
    }

    use test_log::test;

    #[test]
    fn test_empty_span() {
        let span = Span::new(0, 10);
        let program = vec![];

        let expected = flow_high_non_branching(span.start, span.end);
        let result = test_parse_flow(&program, span);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_basic_if() {
        let span = Span::new(0, 30);
        let program = vec![
            FlowNode::jump_if(Span::new(10, 11), arg(), true, 20),
            FlowNode::non_branching(Span::new(20, 30), vec![]),
        ];

        let expected = FlowHigh::composite(vec![
            flow_high_non_branching(0, 10),
            FlowHigh::conditional(Span::new(10, 11), flow_high_non_branching(11, 20)),
            flow_high_non_branching(20, 30),
        ]);
        let result = test_parse_flow(&program, span);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_if_else() {
        let span = Span::new(0, 40);
        let program = vec![
            FlowNode::jump_if(Span::new(10, 11), arg(), true, 25),
            FlowNode::goto(Span::new(22, 25), 30),
            FlowNode::non_branching(Span::new(25, 30), vec![]),
        ];

        let expected = FlowHigh::composite(vec![
            flow_high_non_branching(0, 10),
            FlowHigh::if_else(
                Span::new(10, 11),
                flow_high_non_branching(11, 22),
                flow_high_non_branching(25, 30),
            ),
            flow_high_non_branching(30, 40),
        ]);
        let result = test_parse_flow(&program, span);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_while_simple() {
        let span = Span::new(0, 30);
        let program = vec![
            FlowNode::non_branching(Span::new(5, 10), vec![]),
            FlowNode::jump_if(Span::new(10, 11), arg(), true, 21),
            FlowNode::goto(Span::new(20, 21), 5),
        ];

        let expected = FlowHigh::composite(vec![
            flow_high_non_branching(0, 5),
            FlowHigh::while_loop(
                LoopId(1),
                Some(flow_high_non_branching(5, 10)),
                flow_high_non_branching(11, 20),
                Span::new(10, 11),
            ),
            flow_high_non_branching(21, 30),
        ]);
        let result = test_parse_flow(&program, span);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_while_contains_loop() {
        let span = Span::new(0, 50);
        let program = vec![
            node_non_branching(5, 10),
            FlowNode::jump_if(Span::new(10, 11), arg(), true, 41),
            FlowNode::goto(Span::new(20, 21), 11),
            FlowNode::goto(Span::new(40, 41), 5),
        ];

        let expected = FlowHigh::composite(vec![
            flow_high_non_branching(0, 5),
            FlowHigh::while_loop(
                LoopId(1),
                Some(flow_high_non_branching(5, 10)),
                FlowHigh::composite(vec![
                    FlowHigh::loop_body(LoopId(2), flow_high_non_branching(11, 20)),
                    flow_high_non_branching(21, 40),
                ]),
                Span::new(10, 11),
            ),
            flow_high_non_branching(41, 50),
        ]);
        let result = test_parse_flow(&program, span);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_loop_contains_while() {
        let span = Span::new(0, 50);
        let program = vec![
            node_non_branching(5, 20),
            FlowNode::jump_if(Span::new(20, 21), arg(), true, 31),
            FlowNode::goto(Span::new(30, 31), 5),
            FlowNode::goto(Span::new(40, 41), 5),
        ];

        let expected = FlowHigh::composite(vec![
            flow_high_non_branching(0, 5),
            FlowHigh::loop_body(
                LoopId(1),
                FlowHigh::composite(vec![
                    FlowHigh::while_loop(
                        LoopId(2),
                        Some(flow_high_non_branching(5, 20)),
                        flow_high_non_branching(21, 30),
                        Span::new(20, 21),
                    ),
                    flow_high_non_branching(31, 40),
                ]),
            ),
            flow_high_non_branching(41, 50),
        ]);
        let result = test_parse_flow(&program, span);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_loop() {
        let span = Span::new(0, 30);
        let program = vec![
            node_non_branching(5, 20),
            FlowNode::goto(Span::new(20, 21), 5),
        ];

        let expected = FlowHigh::composite(vec![
            flow_high_non_branching(0, 5),
            FlowHigh::loop_body(LoopId(1), flow_high_non_branching(5, 20)),
            flow_high_non_branching(21, 30),
        ]);
        let result = test_parse_flow(&program, span);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_nested_loop() {
        let span = Span::new(0, 50);
        let program = vec![
            node_non_branching(5, 15),
            node_non_branching(15, 20),
            FlowNode::goto(Span::new(20, 21), 15),
            FlowNode::goto(Span::new(40, 41), 5),
        ];

        let expected = FlowHigh::composite(vec![
            flow_high_non_branching(0, 5),
            FlowHigh::loop_body(
                LoopId(1),
                FlowHigh::composite(vec![
                    flow_high_non_branching(5, 15),
                    FlowHigh::loop_body(LoopId(2), flow_high_non_branching(15, 20)),
                    flow_high_non_branching(21, 40),
                ]),
            ),
            flow_high_non_branching(41, 50),
        ]);
        let result = test_parse_flow(&program, span);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_nested_loop_same_start_point() {
        let span = Span::new(0, 50);
        let program = vec![
            node_non_branching(5, 20),
            FlowNode::goto(Span::new(20, 21), 5),
            FlowNode::goto(Span::new(40, 41), 5),
        ];

        let expected = FlowHigh::composite(vec![
            flow_high_non_branching(0, 5),
            FlowHigh::loop_body(
                LoopId(1),
                FlowHigh::composite(vec![
                    FlowHigh::loop_body(LoopId(2), flow_high_non_branching(5, 20)),
                    flow_high_non_branching(21, 40),
                ]),
            ),
            flow_high_non_branching(41, 50),
        ]);
        let result = test_parse_flow(&program, span);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_two_loops_in_sequence() {
        let span = Span::new(0, 50);
        let program = vec![
            node_non_branching(5, 20),
            FlowNode::goto(Span::new(20, 21), 5),
            node_non_branching(25, 40),
            FlowNode::goto(Span::new(40, 41), 25),
        ];

        let expected = FlowHigh::composite(vec![
            flow_high_non_branching(0, 5),
            FlowHigh::loop_body(LoopId(1), flow_high_non_branching(5, 20)),
            flow_high_non_branching(21, 25),
            FlowHigh::loop_body(LoopId(1), flow_high_non_branching(25, 40)),
            flow_high_non_branching(41, 50),
        ]);
        let result = test_parse_flow(&program, span);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_while_contains_if() {
        let span = Span::new(0, 50);
        let program = vec![
            node_non_branching(5, 10),
            FlowNode::jump_if(Span::new(10, 11), arg(), true, 41),
            FlowNode::jump_if(Span::new(20, 21), arg(), true, 30),
            node_non_branching(30, 40),
            FlowNode::goto(Span::new(40, 41), 5),
        ];

        let expected = FlowHigh::composite(vec![
            flow_high_non_branching(0, 5),
            FlowHigh::while_loop(
                LoopId(1),
                Some(flow_high_non_branching(5, 10)),
                FlowHigh::composite(vec![
                    flow_high_non_branching(11, 20),
                    FlowHigh::conditional(Span::new(20, 21), flow_high_non_branching(21, 30)),
                    flow_high_non_branching(30, 40),
                ]),
                Span::new(10, 11),
            ),
            flow_high_non_branching(41, 50),
        ]);
        let result = test_parse_flow(&program, span);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_if_contains_while() {
        let span = Span::new(0, 60);
        let program = vec![
            // If condition - jump to end if condition is true
            FlowNode::jump_if(Span::new(10, 11), arg(), true, 51),
            // While loop inside if body
            node_non_branching(20, 25), // While condition expression
            FlowNode::jump_if(Span::new(25, 26), arg(), true, 41), // While condition jump
            FlowNode::goto(Span::new(40, 41), 20), // Jump back to while condition
            node_non_branching(51, 60), // While condition expression
        ];

        let expected = FlowHigh::composite(vec![
            flow_high_non_branching(0, 10),
            FlowHigh::conditional(
                Span::new(10, 11),
                FlowHigh::composite(vec![
                    flow_high_non_branching(11, 20),
                    FlowHigh::while_loop(
                        LoopId(1),
                        Some(flow_high_non_branching(20, 25)),
                        flow_high_non_branching(26, 40),
                        Span::new(25, 26),
                    ),
                    flow_high_non_branching(41, 51),
                ]),
            ),
            flow_high_non_branching(51, 60),
        ]);

        let result = test_parse_flow(&program, span);
        assert_eq!(result, expected);
    }

    #[test]
    fn jump_conditionally_to_return_statement() {
        let span = Span::new(0, 30);
        let program = vec![
            FlowNode::jump_if(Span::new(10, 11), arg(), true, 20),
            FlowNode::new_return(Span::new(20, 21)),
        ];

        let expected = FlowHigh::composite(vec![
            flow_high_non_branching(0, 10),
            FlowHigh::conditional(Span::new(10, 11), FlowHigh::return_flow()),
            flow_high_non_branching(11, 20),
            FlowHigh::return_flow(),
            flow_high_non_branching(21, 30),
        ]);
        let result = test_parse_flow(&program, span);
        assert_eq!(result, expected);
    }

    #[test]
    fn jump_conditionally_to_return_statement_from_do_while() {
        let span = Span::new(0, 30);
        let program = vec![
            node_non_branching(5, 15),
            FlowNode::jump_if(Span::new(15, 16), arg(), true, 27),
            FlowNode::jump_if(Span::new(20, 21), arg(), true, 5),
            FlowNode::new_return(Span::new(27, 30)),
        ];

        let expected = FlowHigh::composite(vec![
            flow_high_non_branching(0, 5),
            FlowHigh::do_while_loop(
                LoopId(1),
                FlowHigh::composite(vec![
                    flow_high_non_branching(5, 15),
                    FlowHigh::conditional(Span::new(15, 16), FlowHigh::return_flow()),
                    flow_high_non_branching(16, 20),
                ]),
                Span::new(20, 21),
            ),
            flow_high_non_branching(21, 27),
            FlowHigh::return_flow(),
        ]);
        let result = test_parse_flow(&program, span);
        assert_eq!(result, expected);
    }

    #[test]
    // jumps to a return point within an if statement thas has other non branching elements.
    fn jump_to_return_within_a_if_clause_inside_a_do_while_loop() {
        let span = Span::new(0, 90);
        let program = vec![
            node_non_branching(0, 10),
            node_non_branching(10, 20),
            FlowNode::jump_if(Span::new(20, 30), arg(), true, 50),
            node_non_branching(30, 40),
            FlowNode::goto(Span::new(40, 50), 80),
            node_non_branching(50, 60),
            FlowNode::jump_if(Span::new(60, 70), arg(), true, 10),
            node_non_branching(70, 80),
            FlowNode::new_return(Span::new(80, 90)),
        ];

        let expected = FlowHigh::composite(vec![
            flow_high_non_branching(0, 10),
            FlowHigh::do_while_loop(
                LoopId(1),
                FlowHigh::composite(vec![
                    flow_high_non_branching(10, 20),
                    FlowHigh::conditional(
                        Span::new(20, 30),
                        FlowHigh::composite(vec![
                            flow_high_non_branching(30, 40),
                            FlowHigh::return_flow(),
                        ]),
                    ),
                    flow_high_non_branching(50, 60),
                ]),
                Span::new(60, 70),
            ),
            flow_high_non_branching(70, 80),
            FlowHigh::return_flow(),
        ]);
        let result = test_parse_flow(&program, span);
        assert_eq!(result, expected);
    }

    #[test]
    fn while_with_conditional_continue() {
        let span = Span::new(0, 130);
        let program = vec![
            node_non_branching(0, 10),
            node_non_branching(10, 20),
            FlowNode::jump_if(Span::new(20, 30), arg(), true, 110),
            FlowNode::jump_if(Span::new(30, 40), arg(), true, 120),
            node_non_branching(40, 50),
            FlowNode::jump_if(Span::new(50, 60), arg(), true, 10),
            FlowNode::jump_if(Span::new(60, 70), arg(), true, 90),
            node_non_branching(70, 80),
            FlowNode::goto(Span::new(80, 90), 10),
            node_non_branching(90, 100),
            FlowNode::goto(Span::new(100, 110), 10),
            node_non_branching(110, 120),
            FlowNode::new_return(Span::new(120, 130)),
        ];

        let expected = FlowHigh::composite(vec![
            flow_high_non_branching(0, 10),
            FlowHigh::while_loop(
                LoopId(1),
                Some(flow_high_non_branching(10, 20)),
                FlowHigh::composite(vec![
                    FlowHigh::conditional(Span::new(30, 40), FlowHigh::return_flow()),
                    flow_high_non_branching(40, 50),
                    FlowHigh::conditional(Span::new(50, 60), FlowHigh::Continue(LoopId(1))),
                    FlowHigh::conditional(
                        Span::new(60, 70),
                        FlowHigh::composite(vec![
                            flow_high_non_branching(70, 80),
                            FlowHigh::Continue(LoopId(1)),
                        ]),
                    ),
                    flow_high_non_branching(90, 100),
                ]),
                Span::new(20, 30),
            ),
            flow_high_non_branching(110, 120),
            FlowHigh::return_flow(),
        ]);
        let result = test_parse_flow(&program, span);
        assert_eq!(result, expected);
    }
}
