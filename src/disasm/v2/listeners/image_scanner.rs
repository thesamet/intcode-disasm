use std::collections::HashSet;

use itertools::Itertools;

use crate::disasm::v2::{
    events::{EventSender, ImageAddedEvent, ModelEventListener},
    instructions::{Instruction, Opcode, Operand, ParseError},
    model::ProgramModel,
    Span,
};

#[derive(Debug, Clone)]
pub struct ImageScannerResult {
    pub recognized_functions: Vec<RecognizedFunction>,
    pub data_segments: Vec<Span>,
}

pub(crate) struct ImageScanner {}

#[derive(Debug, Clone)]
pub struct RecognizedFunction {
    pub span: Span,
    pub stack_size: usize,
    pub instructions: Vec<Instruction>,
    pub returns: Option<Span>,
    pub jump_targets: HashSet<usize>,
    pub function_calls: Vec<BaseFunctionCall>,
}

#[derive(Debug, Clone)]
struct BaseFunctionCall {
    span: Span,
    target: Operand,
    return_address: usize,
}

/* The image scanner does an initial first pass over the binary image.
It finds all function spans and all locations for which there is a direct
jump to and from */
impl ModelEventListener for ImageScanner {
    fn on_image_added_event<'a>(
        &mut self,
        model: &mut ProgramModel,
        event: ImageAddedEvent,
        sender: &mut EventSender,
    ) {
        let mut i = 0;
        let image = &model.image;
        let mut data_offsets = vec![];
        let mut recognized_functions = vec![];
        while i < image.len() {
            let Some(stack_size) = recognize_function_start(image, i) else {
                data_offsets.push(i);
                i += 1;
                continue;
            };
            let Ok(f) = scan_from(image, i + 2, stack_size) else {
                data_offsets.push(i);
                i += 1;
                continue;
            };
            i = f.span.end;
            recognized_functions.push(f);
            continue;
        }
        let data_segments = data_offsets
            .iter()
            .map(|o| Span::new(*o, *o + 1))
            .coalesce(|x, y| {
                if x.end == y.start {
                    Ok(Span::new(x.start, y.end))
                } else {
                    Err((x, y))
                }
            })
            .collect_vec();
        let result = ImageScannerResult {
            recognized_functions,
            data_segments,
        };
        model.image_scanner_result = Some(result);
    }
}

fn recognize_function_start(image: &[i128], offset: usize) -> Option<i128> {
    let Ok(instruction) = Instruction::parse(image, offset) else {
        return None;
    };
    if instruction.opcode != Opcode::AdjustRelativeBase {
        return None;
    }
    instruction
        .operands
        .get(0)
        .and_then(|o| o.kind.get_immediate())
        .filter(|r| *r > 0)
}

fn recognize_return(
    image: &[i128],
    offset: usize,
    stack_size: i128,
) -> Result<(Instruction, Instruction), ParseError> {
    let adj_r = Instruction::parse(image, offset)?;
    if adj_r.opcode != Opcode::AdjustRelativeBase {
        return Err(ParseError::NoMatch);
    }
    let Some(negated_stack_size) = adj_r.operands.get(0).and_then(|o| o.kind.get_immediate())
    else {
        return Err(ParseError::InvalidStackAdjustment(offset));
    };
    if stack_size != -negated_stack_size {
        return Err(ParseError::InvalidStackAdjustment(offset));
    }
    let offset = offset + 2;
    let goto = Instruction::parse(image, offset)?;
    let Some(goto_address) = goto.goto_address() else {
        return Err(ParseError::UnexpectedOpAfterAdjustment(goto));
    };
    if goto_address.kind.get_relative_memory() != Some(0) {
        return Err(ParseError::UnexpectedOpAfterAdjustment(goto));
    }
    Ok((adj_r, goto))
}

fn recognize_function_call(
    image: &[i128],
    offset: usize,
) -> Result<(Instruction, Instruction, BaseFunctionCall), ParseError> {
    let set_r = Instruction::parse(image, offset)?;
    let assignment = set_r.as_assignment().ok_or(ParseError::NoMatch)?;
    if assignment.target.kind.get_relative_memory() != Some(0) {
        return Err(ParseError::NoMatch);
    }
    let return_address = assignment
        .source
        .kind
        .get_immediate()
        .ok_or(ParseError::NoMatch)? as usize;
    let goto_op = Instruction::parse(image, set_r.span.end)?;
    if !goto_op.is_goto() {
        return Err(ParseError::NoMatch);
    }
    if return_address != goto_op.span.end {
        return Err(ParseError::NoMatch);
    }
    let function_call = BaseFunctionCall {
        span: Span::new(set_r.span.start, goto_op.span.end),
        target: assignment.target,
        return_address,
    };
    Ok((set_r, goto_op, function_call))
}

fn scan_from(
    image: &[i128],
    start: usize,
    stack_size: i128,
) -> Result<RecognizedFunction, ParseError> {
    let mut queue = vec![start];
    let mut returns = vec![];
    let mut jump_targets = HashSet::new();
    let mut instructions = vec![];
    let mut function_calls = vec![];
    let mut seen = HashSet::new();
    while let Some(offset) = queue.pop() {
        if seen.contains(&offset) {
            continue;
        }
        seen.insert(offset);
        if let Ok((i1, i2)) = recognize_return(image, offset, stack_size) {
            returns.push(Span::new(i1.span.start, i2.span.end));
            instructions.push(i1);
            instructions.push(i2);
            continue;
        } else if let Ok((i1, i2, fc)) = recognize_function_call(image, offset) {
            instructions.push(i1);
            instructions.push(i2);
            function_calls.push(fc);
        } else {
            let instruction = Instruction::parse(image, offset)?;
            if instruction.is_jump() {
                let address = instruction
                    .immediate_goto()
                    .or_else(|| instruction.conditional_immediate_jump());
                if let Some(addr) = address {
                    queue.push(addr);
                    jump_targets.insert(addr);
                }
            }

            if !instruction.is_halt() && !instruction.is_goto() {
                queue.push(instruction.span.end);
            }
            instructions.push(instruction);
        }
    }
    instructions.sort_by_key(|i| i.span.start);
    assert!(returns.len() <= 1);
    Ok(RecognizedFunction {
        span: Span::new(start - 2, instructions.last().unwrap().span.end),
        stack_size: stack_size as usize,
        instructions,
        returns: returns.iter().exactly_one().ok().cloned(),
        jump_targets,
        function_calls,
    })
}

fn draw_triangle(image: &mut [i128], x: usize, y: usize, color: i128) {
    image[y * 16 + x] = color;
    image[(y + 1) * 16 + x] = color;
    image[(y + 2) * 16 + x] = color;
}
