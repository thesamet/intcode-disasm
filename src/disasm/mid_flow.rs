use std::collections::HashMap;

use itertools::Itertools;

use super::low_ir::{Arg, Span};

#[derive(Debug)]
enum ControlFlowError {
    LoopNoBackJump,
    While_MissingBackJump,
    While_NoConditionalJump,
    While_JumpBackDoesNotMatchJumpIf,
    /*
    NoJumpTargets,
    While_NoConditionalJump,
    While_NoBackGoto,
    While_JumpBackDoesNotMatchJumpIf,
    While_MissingBackJump,
    Loop_MissingGoto,
    Loop_MissingBackJump,
    If_NoConditionalJump,
    IfElse_NoConditionalJump,
    IfElse_JumpAboveThen,
    */
}

#[derive(Debug, Clone)]
enum FlowNodeKind {
    NonBranching,
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
        matches!(self, FlowNodeKind::NonBranching)
    }

    fn is_jump_if(&self) -> bool {
        matches!(self, FlowNodeKind::JumpIf { .. })
    }

    fn is_goto(&self) -> bool {
        matches!(self, FlowNodeKind::Goto(_))
    }
}

#[derive(Debug, Clone)]
struct FlowNode {
    kind: FlowNodeKind,
    span: Span,
}

impl FlowNode {
    fn non_branching(span: Span) -> Self {
        FlowNode {
            kind: FlowNodeKind::NonBranching,
            span,
        }
    }

    fn jump_if(span: Span, value: Arg, equal_to: bool, target: usize) -> Self {
        FlowNode {
            kind: FlowNodeKind::JumpIf {
                value,
                equal_to,
                target,
            },
            span,
        }
    }

    fn goto(span: Span, target: usize) -> Self {
        FlowNode {
            kind: FlowNodeKind::Goto(target),
            span,
        }
    }

    fn new_return(span: Span) -> Self {
        FlowNode {
            kind: FlowNodeKind::Return,
            span,
        }
    }
}

#[derive(Debug, Clone)]
struct FlowGraph {
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

    fn build_from(nodes: &[FlowNode]) -> Self {
        let mut graph = FlowGraph {
            nodes: HashMap::new(),
            inbounds: HashMap::new(),
        };
        for node in nodes {
            graph.nodes.insert(node.span.start, node.clone());
            if !node.kind.is_non_branching() {
                let target = match &node.kind {
                    FlowNodeKind::JumpIf { target, .. } => *target,
                    FlowNodeKind::Goto(target) => *target,
                    _ => unreachable!(),
                };
                graph
                    .inbounds
                    .entry(target)
                    .or_default()
                    .push(node.span.start);
            }
        }
        assert!(graph.inbounds.keys().all(|k| graph.nodes.contains_key(k)));
        assert!(nodes
            .iter()
            .filter(|n| matches!(n.kind, FlowNodeKind::Return))
            .all(|n| graph.next(n).is_some()));
        graph
    }
}

impl FlowHigh {
    fn new(span: Span, flows: Vec<FlowHigh>) -> Self {
        FlowHigh::Composite(flows)
    }
}

// These elements represent opcodes that may impact the program counter (location of the next
// opcode to execute).
#[derive(Debug, PartialEq, Clone)]
enum FlowLow {
    NonBranching,
    JumpIf(usize), // a conditional jump to the given address.
    Goto(usize),   // a jump to a given address. Gotos that go backwards create loops, gotos that
    // go forward can be used to skip over the second if "branches". Gotos can also represent
    // break and continue statements from a loop. A goto can also jump to a return statement, and
    // in that case the FlowHigh representation will have a "Return" in that location.
    Return, // a return statement may appear multiple times, within if else clauses, loops, etc.
}

#[derive(Debug, PartialEq, Clone)]
enum FlowHigh {
    NonBranching {
        span: Span, // represents a code range without jumps.
    },
    Composite(Vec<FlowHigh>), // represents multiple non-overlapping flows that execute
    // consecutively.
    While {
        jump_if_span: Span,
        expr: Option<Box<FlowHigh>>,
        body: Box<FlowHigh>,
    },
    Loop {
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
    Break,
    Continue,
}

impl FlowHigh {
    pub fn non_branching(span: Span) -> Self {
        FlowHigh::NonBranching { span }
    }

    fn composite(flows: Vec<FlowHigh>) -> Self {
        FlowHigh::Composite(flows)
    }

    pub fn while_loop(expr: Option<FlowHigh>, body: FlowHigh, jump_if_span: Span) -> Self {
        FlowHigh::While {
            expr: expr.map(Box::new),
            body: Box::new(body),
            jump_if_span,
        }
    }

    pub fn loop_body(body: FlowHigh) -> Self {
        FlowHigh::Loop {
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

fn parse_flow(graph: &FlowGraph, region: Span) -> Result<FlowHigh, ControlFlowError> {
    let (end, result) = parse_flow_inner(graph, region)?;
    if end.start == region.end {
        Ok(result)
    } else {
        unreachable!()
    }
}

fn parse_flow_inner(graph: &FlowGraph, region: Span) -> Result<(Span, FlowHigh), ControlFlowError> {
    let node = graph.nodes.get(&region.start).unwrap();
    let mut result = vec![];
    let mut region = region;
    while region.start < region.end {
        let node = graph.nodes.get(&region.start).unwrap();
        if node.kind.is_non_branching() && graph.inbound_by_jump(node, region).is_empty() {
            result.push(FlowHigh::non_branching(node.span));
            region = region.with_start(node.span.end);
            continue;
        }
        let (next_region, h) = parse_while(graph, region).or_else(|_| parse_loop(graph, region))?;
        result.push(h);
        region = next_region;
    }
    if result.len() == 1 {
        Ok((region, result.into_iter().next().unwrap()))
    } else {
        Ok((region, FlowHigh::composite(result)))
    }
}

fn parse_loop(graph: &FlowGraph, region: Span) -> Result<(Span, FlowHigh), ControlFlowError> {
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
    let body = parse_flow(graph, Span::new(region.start, max_jump_back.start))?;
    Ok((
        region.with_start(max_jump_back.end),
        FlowHigh::loop_body(body),
    ))
}

fn parse_while(graph: &FlowGraph, region: Span) -> Result<(Span, FlowHigh), ControlFlowError> {
    let start_node = graph.nodes.get(&region.start).unwrap();

    let Some(max_jump_back) = graph
        .inbound_by_jump(start_node, region)
        .into_iter()
        .filter(|n| n.kind.is_goto() && region.contains(&n.span))
        .map(|n| n.span)
        .max_by_key(|s| s.start)
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
                .ok_or(ControlFlowError::While_NoConditionalJump)?,
        )
    } else {
        return Err(ControlFlowError::While_NoConditionalJump);
    };

    let FlowNodeKind::JumpIf {
        value: ref _value,
        equal_to: _equal_to,
        target: end_address,
    } = cond_node.kind
    else {
        unreachable!();
    };

    if end_address != max_jump_back.end {
        return Err(ControlFlowError::While_JumpBackDoesNotMatchJumpIf);
    }
    let expr = expr_node.map(|n| parse_flow(graph, n.span)).transpose()?;
    let body = parse_flow(graph, Span::new(cond_node.span.end, max_jump_back.start))?;
    Ok((
        region.with_start(end_address),
        FlowHigh::while_loop(expr, body, cond_node.span),
    ))
}

/*
    let (expr_node, cond_node, end_address) = match start_node.kind {
        FlowNodeKind::JumpIf {
            value,
            equal_to,
            target,
        } => (None, value, target),
        FlowNodeKind::NonBranching =>
            let
            (start_node, graph.nodes.get(&start_node.span.end).unwrap(), 0),
        },
        FlowNodeKind::Goto(target) => {
            return Result::Err(ControlFlowError::While_MissingBackJump);
        },
            let expr_node = graph.nodes.get(&region.start).unwrap();
            let cond_node = graph.nodes.get(&expr_node.span.end).unwrap();
            (Some(expr_node), cond_node, target)
        }

        return Err(ControlFlowError::LoopNoBackJump);
    }

    };
    let Some(jump_if) = graph
        .inbound_by_jump(node, region)
        .into_iter()
        .filter(|n| n.kind.is_goto() && region.contains(&n.span))
        .map(|n| n.span)
        .next()
    else {
        return Err(ControlFlowError::LoopNoBackJump);
    };
    let cond = parse_flow(graph, Span::new(region.start, jump_if.start))?;
    let body = parse_flow(graph, Span::new(jump_if.end, goto.start))?;
    Ok((
        region.with_start(goto.end),
        FlowHigh::while_loop(cond, body, jump_if),
    ))
*/

/*
fn jump_targets(region: Span, inp: &[(Span, FlowLow)]) -> Vec<(usize, Vec<(Span, FlowLow)>)> {
    let mut hm = HashMap::new();

    for (span, flow) in inp {
        match flow {
            FlowLow::JumpIf(target) => {
                println!("{:?} {:?} {:?}", target, region, span);
                assert!(*target >= span.end && *target < region.end && *target >= region.start);
            }
            FlowLow::Goto(target) => {
                assert!(*target >= region.start && *target < region.end);
            }
            _ => {}
        }
    }
    for (span, flow) in inp {
        match flow {
            FlowLow::JumpIf(target) | FlowLow::Goto(target) => {
                hm.entry(*target)
                    .or_insert_with(Vec::new)
                    .push((*span, flow.clone()));
            }
            _ => {}
        }
    }
    hm.into_iter()
        .sorted_by_key(|(target, _)| *target)
        .collect_vec()
}

fn first_jump_target(
    region: Span,
    inp: &[(Span, FlowLow)],
) -> Result<(usize, Vec<(Span, FlowLow)>), ControlFlowError> {
    jump_targets(region, inp)
        .first()
        .cloned()
        .ok_or(ControlFlowError::NoJumpTargets)
}

type LowFlowInput<'a> = (Span, &'a [(Span, FlowLow)]);

fn parse_flow_inner(
    (mut region, mut flow): LowFlowInput,
) -> Result<(LowFlowInput, FlowHigh), ControlFlowError> {
    let mut result = vec![];
    while region.start < region.end {
        if flow.is_empty() {
            result.push(FlowHigh::non_branching(region));
            break;
        }
        let lowest_jump_target = first_jump_target(region, flow)?.0;
        let first_jump_addr = flow.first().unwrap().0.start;
        let start = lowest_jump_target.min(first_jump_addr);
        if start > region.start {
            result.push(FlowHigh::non_branching(Span::new(region.start, start)));
            region = Span::new(start, region.end);
            continue;
        }
        let (new_input, high_flow) = parse_while((region, flow))
            .or_else(|_| parse_loop((region, flow)))
            .or_else(|_| parse_if((region, flow)))
            .or_else(|_| parse_if_else((region, flow)))?;
        result.push(high_flow);
        (region, flow) = new_input;
    }
    assert!(!result.is_empty());
    let output = if result.len() == 1 {
        result.into_iter().next().unwrap()
    } else {
        FlowHigh::composite(result)
    };
    Ok(((region, flow), output))
}

fn parse_flow(region: Span, flows: &[(Span, FlowLow)]) -> Result<FlowHigh, ControlFlowError> {
    let ((region, input), output) = parse_flow_inner((region, flows))?;
    assert!(region.start != region.end);
    assert!(input.is_empty());
    Ok(output)
}

fn input_result<'a>(new_region: Span, original_flows: &'a [(Span, FlowLow)]) -> LowFlowInput<'a> {
    let start_pos = original_flows
        .iter()
        .position(|(s, _)| s.start >= new_region.start && s.end <= new_region.end)
        .unwrap_or(original_flows.len());
    (new_region, &original_flows[start_pos..])
}

fn parse_while(
    input @ (region, flow): LowFlowInput,
) -> Result<(LowFlowInput, FlowHigh), ControlFlowError> {
    let (first_jump_target, from) = first_jump_target(region, flow)?;
    if first_jump_target != region.start {
        return Err(ControlFlowError::While_MissingBackJump);
    }

    let Some((cond_span, FlowLow::JumpIf(body_end))) = flow.first() else {
        return Err(ControlFlowError::While_NoConditionalJump);
    };

    let Some((jump_back_span, FlowLow::Goto(_))) = flow.last() else {
        return Err(ControlFlowError::While_NoBackGoto);
    };

    if jump_back_span.end != *body_end {
        return Err(ControlFlowError::While_JumpBackDoesNotMatchJumpIf);
    }
    assert!(cond_span.start < jump_back_span.start);
    let expr = FlowHigh::non_branching(Span::new(region.start, cond_span.start));
    let while_body_span = Span::new(cond_span.end, jump_back_span.start);
    let body_flow = &flow[1..];
    let body_flow_end = body_flow
        .iter()
        .position(|(s, _)| !while_body_span.contains(s))
        .unwrap_or(body_flow.len());
    let body_flow = &body_flow[0..body_flow_end];

    println!("Parse while inner");
    let (input, body) = parse_flow_inner((while_body_span, body_flow))?;
    println!("Parse while made it");
    Ok((
        input_result(Span::new(cond_span.end, region.end), flow),
        FlowHigh::while_loop(expr, body, *cond_span),
    ))
}

fn parse_loop((region, flow): LowFlowInput) -> Result<(LowFlowInput, FlowHigh), ControlFlowError> {
    let (first_jump_target, from) = first_jump_target(region, flow)?;
    if first_jump_target != region.start {
        return Err(ControlFlowError::Loop_MissingBackJump);
    }
    let Some((jump_back_span, FlowLow::Goto(_))) = from.last() else {
        return Err(ControlFlowError::Loop_MissingGoto);
    };
    let body_span = Span::new(region.start, jump_back_span.start);
    let body_flow_end = flow
        .iter()
        .position(|(s, _)| !body_span.contains(s))
        .unwrap_or(flow.len());
    let body_flow = &flow[0..body_flow_end];
    let (input, body) = parse_flow_inner((body_span, body_flow))?;
    let new_region = Span::new(jump_back_span.end, region.end);
    let new_flows = &flow[(flow.iter().position(|(s, _)| s == jump_back_span).unwrap() + 1)..];
    Ok(((new_region, new_flows), FlowHigh::loop_body(body)))
}

fn parse_if(
    input @ (region, flow): LowFlowInput,
) -> Result<(LowFlowInput, FlowHigh), ControlFlowError> {
    let Some((jump_if_span, FlowLow::JumpIf(then_end))) = flow.first() else {
        return Err(ControlFlowError::If_NoConditionalJump);
    };
    if jump_if_span.start != region.start {
        return Err(ControlFlowError::If_NoConditionalJump);
    }
    let then_span = Span::new(jump_if_span.end, *then_end);
    let then_flow_end = flow
        .iter()
        .position(|(s, _)| !then_span.contains(s))
        .unwrap_or(flow.len());
    let then_flow = &flow[1..then_flow_end];
    let (input, then) = parse_flow_inner((then_span, then_flow))?;
    Ok((input, FlowHigh::conditional(*jump_if_span, then)))
}

fn parse_if_else(
    input @ (region, flow): LowFlowInput,
) -> Result<(LowFlowInput, FlowHigh), ControlFlowError> {
    let Some((jump_if_span, FlowLow::JumpIf(else_start))) = flow.first() else {
        return Err(ControlFlowError::IfElse_NoConditionalJump);
    };
    if jump_if_span.start != region.start {
        return Err(ControlFlowError::IfElse_NoConditionalJump);
    }
    let Some((
        Span {
            start: then_end, ..
        },
        FlowLow::Goto(else_end),
    )) = flow.iter().find(|(s, _)| s.end == *else_start)
    else {
        return Err(ControlFlowError::IfElse_JumpAboveThen);
    };
    let then_span = Span::new(jump_if_span.end, *then_end);
    let then_flow_end = flow
        .iter()
        .position(|(s, _)| !then_span.contains(s))
        .unwrap_or(flow.len());
    let then_flow = &flow[1..then_flow_end];
    let (input, then) = parse_flow_inner((then_span, then_flow))?;

    let else
    let else_flow_end = flow
        .iter()
        .position(|(s, _)| !else_span.contains(s))
        .unwrap_or(flow.len());
    let else_flow = &flow[then_flow_end..else_flow_end];
    let (input, els) = parse_flow_inner((else_span, else_flow))?;
    Ok((input, FlowHigh::if_else(*jump_if_span, then, els)))
}
*/

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
                    kind: FlowNodeKind::NonBranching,
                    span: Span::new(current_start, node.span.start),
                });
            }

            nodes.push(node.clone());

            current_start = node.span.end;
        }

        if current_start < region.end {
            // Fill the remaining gap with NonBranching
            nodes.push(FlowNode {
                kind: FlowNodeKind::NonBranching,
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

    #[test]
    fn test_empty_span() {
        let span = Span::new(0, 10);
        let program = vec![];

        let expected = FlowHigh::non_branching(span);
        let result = test_parse_flow(&program, span);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_basic_if() {
        let span = Span::new(0, 30);
        let program = vec![FlowNode::jump_if(Span::new(10, 11), arg(), true, 20)];

        let expected = FlowHigh::composite(vec![
            FlowHigh::non_branching(Span::new(0, 10)),
            FlowHigh::conditional(
                Span::new(10, 11),
                FlowHigh::non_branching(Span::new(11, 20)),
            ),
            FlowHigh::non_branching(Span::new(20, 30)),
        ]);
        let result = test_parse_flow(&program, span);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_if_else() {
        let span = Span::new(0, 40);
        let program = vec![
            FlowNode::jump_if(Span::new(10, 11), arg(), true, 25),
            FlowNode::goto(Span::new(20, 21), 30),
        ];

        let expected = FlowHigh::composite(vec![
            FlowHigh::non_branching(Span::new(0, 10)),
            FlowHigh::if_else(
                Span::new(10, 11),
                FlowHigh::non_branching(Span::new(11, 20)),
                FlowHigh::non_branching(Span::new(25, 30)),
            ),
            FlowHigh::non_branching(Span::new(30, 40)),
        ]);
        let result = test_parse_flow(&program, span);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_while_simple() {
        let span = Span::new(0, 30);
        let program = vec![
            FlowNode::non_branching(Span::new(5, 10)),
            FlowNode::jump_if(Span::new(10, 11), arg(), true, 21),
            FlowNode::goto(Span::new(20, 21), 5),
        ];

        let expected = FlowHigh::composite(vec![
            FlowHigh::non_branching(Span::new(0, 5)),
            FlowHigh::while_loop(
                Some(FlowHigh::non_branching(Span::new(5, 10))),
                FlowHigh::non_branching(Span::new(11, 20)),
                Span::new(10, 11),
            ),
            FlowHigh::non_branching(Span::new(21, 30)),
        ]);
        let result = test_parse_flow(&program, span);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_while_contains_loop() {
        let span = Span::new(0, 50);
        let program = vec![
            FlowNode::non_branching(Span::new(5, 10)),
            FlowNode::jump_if(Span::new(10, 11), arg(), true, 41),
            FlowNode::goto(Span::new(20, 21), 11),
            FlowNode::goto(Span::new(40, 41), 5),
        ];

        let expected = FlowHigh::composite(vec![
            FlowHigh::non_branching(Span::new(0, 5)),
            FlowHigh::while_loop(
                Some(FlowHigh::non_branching(Span::new(5, 10))),
                FlowHigh::composite(vec![
                    FlowHigh::loop_body(FlowHigh::non_branching(Span::new(11, 20))),
                    FlowHigh::non_branching(Span::new(21, 40)),
                ]),
                Span::new(10, 11),
            ),
            FlowHigh::non_branching(Span::new(41, 50)),
        ]);
        let result = test_parse_flow(&program, span);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_loop_contains_while() {
        let span = Span::new(0, 50);
        let program = vec![
            FlowNode::non_branching(Span::new(5, 10)),
            FlowNode::jump_if(Span::new(20, 21), arg(), true, 31),
            FlowNode::goto(Span::new(30, 31), 5),
            FlowNode::goto(Span::new(40, 41), 5),
        ];

        let expected = FlowHigh::composite(vec![
            FlowHigh::non_branching(Span::new(0, 5)),
            FlowHigh::loop_body(FlowHigh::composite(vec![
                FlowHigh::while_loop(
                    None,
                    FlowHigh::non_branching(Span::new(5, 10)),
                    Span::new(10, 11),
                ),
                FlowHigh::non_branching(Span::new(11, 20)),
            ])),
            FlowHigh::while_loop(
                Some(FlowHigh::non_branching(Span::new(20, 21))),
                FlowHigh::non_branching(Span::new(21, 40)),
                Span::new(20, 21),
            ),
            FlowHigh::non_branching(Span::new(41, 50)),
        ]);
        let result = test_parse_flow(&program, span);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_loop() {
        let span = Span::new(0, 30);
        let program = vec![
            FlowNode::non_branching(Span::new(5, 20)),
            FlowNode::goto(Span::new(20, 21), 5),
        ];

        let expected = FlowHigh::composite(vec![
            FlowHigh::non_branching(Span::new(0, 5)),
            FlowHigh::loop_body(FlowHigh::non_branching(Span::new(5, 20))),
            FlowHigh::non_branching(Span::new(21, 30)),
        ]);
        let result = test_parse_flow(&program, span);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_nested_loop() {
        let span = Span::new(0, 50);
        let program = vec![
            FlowNode::non_branching(Span::new(5, 15)),
            FlowNode::non_branching(Span::new(15, 20)),
            FlowNode::goto(Span::new(20, 21), 15),
            FlowNode::goto(Span::new(40, 41), 5),
        ];

        let expected = FlowHigh::composite(vec![
            FlowHigh::non_branching(Span::new(0, 5)),
            FlowHigh::loop_body(FlowHigh::composite(vec![
                FlowHigh::non_branching(Span::new(5, 15)),
                FlowHigh::loop_body(FlowHigh::non_branching(Span::new(15, 20))),
                FlowHigh::non_branching(Span::new(21, 40)),
            ])),
            FlowHigh::non_branching(Span::new(41, 50)),
        ]);
        let result = test_parse_flow(&program, span);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_nested_loop_same_start_point() {
        let span = Span::new(0, 50);
        let program = vec![
            FlowNode::non_branching(Span::new(5, 20)),
            FlowNode::goto(Span::new(20, 21), 5),
            FlowNode::goto(Span::new(40, 41), 5),
        ];

        let expected = FlowHigh::composite(vec![
            FlowHigh::non_branching(Span::new(0, 5)),
            FlowHigh::loop_body(FlowHigh::composite(vec![
                FlowHigh::loop_body(FlowHigh::non_branching(Span::new(5, 20))),
                FlowHigh::non_branching(Span::new(21, 40)),
            ])),
            FlowHigh::non_branching(Span::new(41, 50)),
        ]);
        let result = test_parse_flow(&program, span);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_two_loops_in_sequence() {
        let span = Span::new(0, 50);
        let program = vec![
            FlowNode::non_branching(Span::new(5, 20)),
            FlowNode::goto(Span::new(20, 21), 5),
            FlowNode::non_branching(Span::new(25, 40)),
            FlowNode::goto(Span::new(40, 41), 25),
        ];

        let expected = FlowHigh::composite(vec![
            FlowHigh::non_branching(Span::new(0, 5)),
            FlowHigh::loop_body(FlowHigh::non_branching(Span::new(5, 20))),
            FlowHigh::non_branching(Span::new(21, 25)),
            FlowHigh::loop_body(FlowHigh::non_branching(Span::new(25, 40))),
            FlowHigh::non_branching(Span::new(41, 50)),
        ]);
        let result = test_parse_flow(&program, span);
        assert_eq!(result, expected);
    }
}
