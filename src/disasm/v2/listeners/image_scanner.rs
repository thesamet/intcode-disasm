use std::collections::HashSet;

use itertools::Itertools;

use crate::disasm::v2::{
    events::{self, ImageAddedEvent, ModelEventListener},
    instructions::{Instruction, InstructionId, Opcode, Operand, ParseError},
    model::ProgramModel,
    Span,
};

#[derive(Debug, Clone)]
pub struct ImageScannerResult {
    pub recognized_functions: Vec<RecognizedFunction>,
    pub data_segments: Vec<Span>,
}

pub(crate) struct ImageScanner {}
impl ImageScanner {
    pub(crate) fn new() -> Self {
        Self {}
    }
}

#[derive(Debug, Clone)]
pub struct RecognizedFunction {
    pub span: Span,
    pub stack_size: usize,
    pub instructions: Vec<Instruction>,
    // The span of the return starts at the R adjustment, and ends after the goto.
    pub return_span: Option<Span>,
    pub jump_targets: HashSet<usize>,
    // Locations from which a jump (conditional or unconditional) is taken.
    pub jump_instructions: Vec<Instruction>,
    pub function_calls: Vec<BaseFunctionCall>,
    pub halts: Vec<Span>,
}

#[derive(Debug, Clone)]
pub struct BaseFunctionCall {
    pub span: Span,
    pub target: Operand,
    pub return_address: usize,
}

/* The image scanner does an initial first pass over the binary image.
It finds all function spans and all locations for which there is a direct
jump to and from */
impl ModelEventListener for ImageScanner {
    fn on_image_added_event<'a>(
        &mut self,
        model: &mut ProgramModel,
        _event: ImageAddedEvent,
        sender: &mut events::Sender,
    ) {
        let mut i = 0;
        let image = &model.get_image();
        let mut data_offsets = vec![];
        let mut recognized_functions = vec![];
        while i < image.len() {
            let Some(stack_size) = recognize_function_start(image, i) else {
                data_offsets.push(i);
                i += 1;
                continue;
            };
            let Ok(mut f) = scan_from(image, i, stack_size) else {
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
        model.set_image_scanner_result(result, sender);
    }
}

fn recognize_function_start(image: &[i128], offset: usize) -> Option<i128> {
    let Ok(instruction) = Instruction::parse(image, offset) else {
        return None;
    };
    if instruction.opcode != Opcode::AdjustRelativeBase {
        return None;
    }
    instruction.relative_base_adjustment().filter(|r| *r > 0)
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
    let Some(negated_stack_size) = adj_r.relative_base_adjustment() else {
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
        target: goto_op.goto_address().unwrap(),
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
    let mut jump_instructions = vec![];
    let mut halts = vec![];
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
            queue.push(fc.return_address);
            instructions.push(i1);
            instructions.push(i2);
            function_calls.push(fc);
        } else {
            let instruction = Instruction::parse(image, offset)?;
            if instruction.is_jump() {
                let address = instruction
                    .immediate_goto()
                    .or_else(|| instruction.conditional_jump_immediate_address());
                if let Some(addr) = address {
                    queue.push(addr);
                    jump_instructions.push(instruction.clone());
                    jump_targets.insert(addr);
                }
            } else if instruction.is_halt() {
                halts.push(instruction.span);
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
        span: Span::new(start, instructions.last().unwrap().span.end),
        stack_size: stack_size as usize,
        instructions,
        return_span: returns.iter().exactly_one().ok().cloned(),
        jump_targets,
        jump_instructions,
        function_calls,
        halts,
    })
}

#[cfg(test)]
mod tests {
    use events::Event;

    use super::*;
    use crate::disasm::{parser, v2::dispatching::EventPublisher};

    fn parse_and_scan(code: &str) -> ImageScannerResult {
        let binary = parser::compile(code);
        let mut model = ProgramModel::new();
        let scanner = ImageScanner {};
        let mut publisher = EventPublisher::<Event, ProgramModel>::new();
        publisher.add_listener(Box::new(scanner));
        model.load_image(&binary, &mut publisher);
        publisher.process_events(&mut model);
        model.get_image_scanner_result().clone()
    }

    #[test]
    fn test_simple_function() {
        let result = parse_and_scan(
            r#"
            R += 5
            [R+2] = [R+3] + [R+4]
            [R+2] = [R+3] + [R+4]
            R -= 5
            goto [R]
            "#,
        );
        assert_eq!(result.recognized_functions.len(), 1);
        let function = &result.recognized_functions[0];
        assert_eq!(function.stack_size, 5);
        assert_eq!(function.return_span.unwrap().start, 10);
        assert_eq!(function.instructions.len(), 5);
    }

    #[test]
    fn test_function_with_call() {
        let result = parse_and_scan(
            r#"
            R += 5      ;0
            [R+1] = 42  ;2
            [R] = @ret  ;6
            goto @other_func   ; 10
            ret:
            R -= 5             ; 13
            goto [R]
            other_func:
            R += 3
            [R-1] = [R-2] + 1
            R -= 3
            goto [R]
            "#,
        );
        assert_eq!(result.recognized_functions.len(), 2);
        let main = &result.recognized_functions[0];
        let other = &result.recognized_functions[1];

        assert_eq!(main.stack_size, 5);
        assert_eq!(other.stack_size, 3);

        assert_eq!(main.function_calls.len(), 1);
        assert_eq!(main.function_calls[0].return_address, 13);
    }

    #[test]
    fn test_function_with_jumps() {
        let result = parse_and_scan(
            r#"
            R += 5                   ; 0
            if [R+1] goto @branch    ; 2
            [R+2] = 42               ; 5
            goto @merge              ; 9
            branch:
            [R+2] = 100              ; 12
            merge:
            R -= 5                   ; 16
            goto [R]                 ; 18
            "#,
        );
        assert_eq!(result.recognized_functions.len(), 1);
        let function = &result.recognized_functions[0];

        assert_eq!(function.jump_targets.len(), 2);
        assert!(function.jump_targets.contains(&12)); // branch
        assert!(function.jump_targets.contains(&16)); // merge
    }

    #[test]
    fn test_data_segments() {
        let result = parse_and_scan(
            r#"
            DATA 99
            DATA 1, 2, 3, 4
            R += 5         ; 5
            [R+1] = 42     ; 7
            R -= 5         ; 11
            goto [R]       ; 13
            DATA 99        ; 16
            DATA 5, 6, 7, 8
            "#,
        );

        assert_eq!(result.recognized_functions.len(), 1);
        assert_eq!(result.data_segments.len(), 2);

        assert_eq!(result.data_segments[0].start, 0);
        assert_eq!(result.data_segments[0].end, 5);

        assert_eq!(result.data_segments[1].start, 16);
        assert_eq!(result.data_segments[1].end, 21);
    }

    #[test]
    fn test_another_funcion_call() {
        let result = parse_and_scan(
            r#"
            ; Main Function (Offset 0)
            main:
            R += 5
            ; Offset 2
            [R+1] = 111 ; Arg 1
            ; Offset 6
            [R+2] = 222 ; Arg 2
            ; Offset 10
            [R] = @main_ret ; Set return address
            ; Offset 14
            goto @callee ; Call
            ; Offset 17
            main_ret:
            output [R+1] ; Use return value
            ; Offset 19
            R -= 5
            ; Offset 21
            goto [R]

            ; Callee Function (Offset 24)
            callee:
            R += 4 ; Stack frame for locals + args
            ; Offset 26
            [R-1] = [R-5] ; Access arg 1 ([R+1] from caller -> [R-5] in callee)
            ; Offset 30
            [R-2] = [R-6] ; Access arg 2 ([R+2] from caller -> [R-6] in callee)
            ; Offset 34
            [R-3] = [R-1] + [R-2] ; Local calc
            ; Offset 38
            [R-5] = [R-3] ; Put result in return slot 1 ([R-5] in callee -> [R+1] in caller)
            ; Offset 42
            R -= 4
            ; Offset 44
            goto [R]
            "#,
        );
        assert_eq!(result.recognized_functions.len(), 2);
        let main = &result.recognized_functions[0];
        let other = &result.recognized_functions[1];

        assert_eq!(main.stack_size, 5);
        assert_eq!(main.span, Span::new(0, 24));
        assert_eq!(other.stack_size, 4);
        assert_eq!(other.span, Span::new(24, 47));

        assert_eq!(main.function_calls.len(), 1);
        assert_eq!(main.function_calls[0].return_address, 17);
    }
}
