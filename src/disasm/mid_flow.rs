use std::collections::HashMap;

use itertools::Itertools;

use super::low_ir::{Arg, Span};

#[derive(Debug)]
enum ControlFlowError {
    LoopNoBackJump,
    WhileNoConditionalJump,
    WhileJumpBackDoesNotMatchJumpIf,
    IfNoConditionalJump,
}

#[derive(Debug, Clone)]
pub enum FlowNodeKind {
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
pub struct FlowNode {
    pub kind: FlowNodeKind,
    pub span: Span,
}

impl FlowNode {
    pub fn non_branching(span: Span) -> Self {
        FlowNode {
            kind: FlowNodeKind::NonBranching,
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
    fn new(span: Span, flows: Vec<FlowHigh>) -> Self {
        FlowHigh::Composite(flows)
    }
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

pub fn parse_flow(graph: &FlowGraph, region: Span) -> Result<FlowHigh, ControlFlowError> {
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
        let (next_region, h) = parse_while(graph, region)
            .or_else(|_| parse_loop(graph, region))
            .or_else(|_| parse_if(graph, region))?;
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
    println!("Parse loop {:?}", region);
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
    println!("Parse while {:?}", region);
    let start_node = graph.nodes.get(&region.start).unwrap();
    println!("  start_node {:?}", start_node);

    let Some(max_jump_back) = graph
        .inbound_by_jump(start_node, region)
        .into_iter()
        .filter(|n| n.kind.is_goto() && region.contains(&n.span))
        .map(|n| n.span)
        .max_by_key(|s| s.start)
    else {
        return Err(ControlFlowError::LoopNoBackJump);
    };

    println!("  max_jump_back {:?}", max_jump_back);

    let (expr_node, cond_node) = if start_node.kind.is_jump_if() {
        (None, start_node)
    } else if start_node.kind.is_non_branching() {
        println!("  next_node: {:?}", graph.next(start_node));
        (
            Some(start_node),
            graph
                .next(start_node)
                .filter(|n| n.kind.is_jump_if())
                .ok_or(ControlFlowError::WhileNoConditionalJump)?,
        )
    } else {
        println!("  no cond jump");
        return Err(ControlFlowError::WhileNoConditionalJump);
    };

    println!("  cond_node and expr_node");

    let FlowNodeKind::JumpIf {
        value: ref _value,
        equal_to: _equal_to,
        target: end_address,
    } = cond_node.kind
    else {
        unreachable!();
    };

    if end_address != max_jump_back.end {
        return Err(ControlFlowError::WhileJumpBackDoesNotMatchJumpIf);
    }
    let body_span = Span::new(cond_node.span.end, max_jump_back.start);
    println!(
        "  Detected while loop expr_span={:?} body_span={:?} end_address={:?}",
        expr_node.map(|x| x.span),
        body_span,
        end_address
    );
    let expr = expr_node.map(|n| parse_flow(graph, n.span)).transpose()?;
    let body = parse_flow(graph, body_span)?;
    Ok((
        region.with_start(end_address),
        FlowHigh::while_loop(expr, body, cond_node.span),
    ))
}

fn parse_if(graph: &FlowGraph, region: Span) -> Result<(Span, FlowHigh), ControlFlowError> {
    println!("Parse if {:?}", region);
    let node = graph.nodes.get(&region.start).unwrap();
    let FlowNodeKind::JumpIf {
        value: ref _value,
        equal_to: _equal_to,
        target: jump_target,
    } = node.kind
    else {
        return Err(ControlFlowError::IfNoConditionalJump);
    };

    // Check if there's a goto that jumps from the end of then block to after the else block
    let then_span = Span::new(node.span.end, jump_target);

    // Find if there's a goto at the end of the then branch
    let goto_node = graph
        .nodes
        .values()
        .find(|n| n.span.end == jump_target && n.kind.is_goto());

    if let Some(goto_node) = goto_node {
        // This is an if-else structure
        let FlowNodeKind::Goto(else_end) = goto_node.kind else {
            unreachable!();
        };

        // Adjust the then_span to end at the goto
        let then_span = Span::new(node.span.end, goto_node.span.start);
        let else_span = Span::new(jump_target, else_end);

        let then = parse_flow(graph, then_span)?;
        let els = parse_flow(graph, else_span)?;

        Ok((
            region.with_start(else_end),
            FlowHigh::if_else(node.span, then, els),
        ))
    } else {
        // This is a simple if structure
        let then = parse_flow(graph, then_span)?;
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
        for node in nodes.iter() {
            println!("{:?}", node);
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
        let program = vec![
            FlowNode::jump_if(Span::new(10, 11), arg(), true, 20),
            FlowNode::non_branching(Span::new(20, 30)),
        ];

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
            FlowNode::goto(Span::new(22, 25), 30),
            FlowNode::non_branching(Span::new(25, 30)),
        ];

        let expected = FlowHigh::composite(vec![
            FlowHigh::non_branching(Span::new(0, 10)),
            FlowHigh::if_else(
                Span::new(10, 11),
                FlowHigh::non_branching(Span::new(11, 22)),
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
            FlowNode::non_branching(Span::new(5, 20)),
            FlowNode::jump_if(Span::new(20, 21), arg(), true, 31),
            FlowNode::goto(Span::new(30, 31), 5),
            FlowNode::goto(Span::new(40, 41), 5),
        ];

        let expected = FlowHigh::composite(vec![
            FlowHigh::non_branching(Span::new(0, 5)),
            FlowHigh::loop_body(FlowHigh::composite(vec![
                FlowHigh::while_loop(
                    Some(FlowHigh::non_branching(Span::new(5, 20))),
                    FlowHigh::non_branching(Span::new(21, 30)),
                    Span::new(20, 21),
                ),
                FlowHigh::non_branching(Span::new(31, 40)),
            ])),
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

    #[test]
    fn test_while_contains_if() {
        let span = Span::new(0, 50);
        let program = vec![
            FlowNode::non_branching(Span::new(5, 10)),
            FlowNode::jump_if(Span::new(10, 11), arg(), true, 41),
            FlowNode::jump_if(Span::new(20, 21), arg(), true, 30),
            FlowNode::non_branching(Span::new(30, 40)),
            FlowNode::goto(Span::new(40, 41), 5),
        ];

        let expected = FlowHigh::composite(vec![
            FlowHigh::non_branching(Span::new(0, 5)),
            FlowHigh::while_loop(
                Some(FlowHigh::non_branching(Span::new(5, 10))),
                FlowHigh::composite(vec![
                    FlowHigh::non_branching(Span::new(11, 20)),
                    FlowHigh::conditional(
                        Span::new(20, 21),
                        FlowHigh::non_branching(Span::new(21, 30)),
                    ),
                    FlowHigh::non_branching(Span::new(30, 40)),
                ]),
                Span::new(10, 11),
            ),
            FlowHigh::non_branching(Span::new(41, 50)),
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
            FlowNode::non_branching(Span::new(20, 25)), // While condition expression
            FlowNode::jump_if(Span::new(25, 26), arg(), true, 41), // While condition jump
            FlowNode::goto(Span::new(40, 41), 20),      // Jump back to while condition
            FlowNode::non_branching(Span::new(51, 60)), // While condition expression
        ];

        let expected = FlowHigh::composite(vec![
            FlowHigh::non_branching(Span::new(0, 10)),
            FlowHigh::conditional(
                Span::new(10, 11),
                FlowHigh::composite(vec![
                    FlowHigh::non_branching(Span::new(11, 20)),
                    FlowHigh::while_loop(
                        Some(FlowHigh::non_branching(Span::new(20, 25))),
                        FlowHigh::non_branching(Span::new(26, 40)),
                        Span::new(25, 26),
                    ),
                    FlowHigh::non_branching(Span::new(41, 51)),
                ]),
            ),
            FlowHigh::non_branching(Span::new(51, 60)),
        ]);

        let result = test_parse_flow(&program, span);
        assert_eq!(result, expected);
    }
}
