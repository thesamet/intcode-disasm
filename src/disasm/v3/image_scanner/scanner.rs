use super::result::{
    BaseFunctionCall, DataSegment, DataType, ImageScannerResult, RecognizedFunction,
};
use crate::disasm::v3::common::Span;
use crate::disasm::v3::id_types::FunctionId;
use crate::disasm::v3::model::{ImageScannerComplete, InitialState, Model};
use crate::disasm::v3::native::{NativeInstruction, Opcode, Operand, OperandKind, ParseError};
use crate::disasm::Error;
use itertools::Itertools;
use log::{debug, info};
use std::collections::{HashMap, HashSet};

/// Analyzes the raw program image to identify functions and data segments
pub struct ImageScanner {
    model: Model<InitialState>,
}

impl ImageScanner {
    pub fn new(model: Model<InitialState>) -> Self {
        Self { model }
    }

    fn image(&self) -> &Vec<i128> {
        self.model.image()
    }

    pub fn run(model: Model<InitialState>) -> Result<Model<ImageScannerComplete>, Error> {
        Self::new(model).scan()
    }

    fn scan(self) -> Result<Model<ImageScannerComplete>, Error> {
        debug!("Starting image scanning...");
        let image = self.image();

        // Scan for functions and data segments
        let mut i = 0;
        let mut data_offsets = vec![];
        let mut recognized_function_details = vec![];

        while i < image.len() {
            if let Some(stack_size) = self.recognize_function_start(i) {
                match self.scan_from(i, stack_size) {
                    Ok(f) => {
                        i = f.span.end;
                        recognized_function_details.push(f);
                        continue;
                    }
                    Err(_) => {
                        data_offsets.push(i);
                        i += 1;
                        continue;
                    }
                }
            } else {
                data_offsets.push(i);
                i += 1;
                continue;
            }
        }

        // Process data segments
        let data_segments = data_offsets
            .iter()
            .map(|o| DataSegment {
                start: *o,
                end: *o + 1,
                data_type: DataType::Data,
            })
            .coalesce(|x, y| {
                if x.end == y.start {
                    Ok(DataSegment {
                        start: x.start,
                        end: y.end,
                        data_type: DataType::Data,
                    })
                } else {
                    Err((x, y))
                }
            })
            .collect::<Vec<_>>();

        // Create function IDs and mappings
        let mut address_to_function = HashMap::new();
        let mut function_to_address = HashMap::new();
        let mut recognized_functions = Vec::new();
        let mut function_details = HashMap::new();

        for f in recognized_function_details {
            let function_id = FunctionId::new(f.span.start);
            let address = f.span.start;

            address_to_function.insert(address, function_id);
            function_to_address.insert(function_id, address);
            function_details.insert(function_id, f);
            recognized_functions.push(function_id);
        }

        info!(
            "Image scanning complete. Found {} functions and {} data segments",
            recognized_functions.len(),
            data_segments.len()
        );

        // Create the image scanner result
        let result = ImageScannerResult {
            data_segments,
            address_to_function,
            recognized_functions: function_details,
            image: image.to_vec(),
        };

        // Return a new model with the updated state
        Ok(self.model.with_image_scanner_result(result))
    }

    /// Recognizes a function start by looking for R += N instruction
    fn recognize_function_start(&self, offset: usize) -> Option<i128> {
        let Ok(instruction) = NativeInstruction::parse(self.image(), offset) else {
            return None;
        };
        if instruction.opcode() != Opcode::AdjustRelativeBase {
            return None;
        }
        instruction.relative_base_adjustment().filter(|r| *r > 0)
    }

    /// Recognizes a function return sequence (R -= N; goto [R])
    fn recognize_return(
        &self,
        offset: usize,
        stack_size: i128,
    ) -> Result<(NativeInstruction, NativeInstruction), ParseError> {
        let adj_r = NativeInstruction::parse(self.image(), offset)?;
        if adj_r.opcode() != Opcode::AdjustRelativeBase {
            return Err(ParseError::NoMatch);
        }
        let Some(negated_stack_size) = adj_r.relative_base_adjustment() else {
            return Err(ParseError::InvalidStackAdjustment(offset));
        };
        if stack_size != -negated_stack_size {
            return Err(ParseError::InvalidStackAdjustment(offset));
        }
        let offset = offset + 2;
        let goto = NativeInstruction::parse(self.image(), offset)?;
        let Some(goto_address) = goto.goto_address() else {
            return Err(ParseError::UnexpectedOpAfterAdjustment);
        };
        if goto_address.kind.get_relative_memory() != Some(0) {
            return Err(ParseError::UnexpectedOpAfterAdjustment);
        }
        Ok((adj_r, goto))
    }

    /// Recognizes a function call sequence ([R] = return_addr; goto func)
    fn recognize_function_call(
        &self,
        offset: usize,
    ) -> Result<(NativeInstruction, NativeInstruction, BaseFunctionCall), ParseError> {
        let set_r = NativeInstruction::parse(self.image(), offset)?;
        let assignment = set_r.as_assignment().ok_or(ParseError::NoMatch)?;
        if assignment.target.kind.get_relative_memory() != Some(0) {
            return Err(ParseError::NoMatch);
        }
        let return_address = assignment
            .source
            .kind
            .get_immediate()
            .ok_or(ParseError::NoMatch)? as usize;
        let goto_op = NativeInstruction::parse(self.image(), set_r.span.end)?;
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

    /// Scans a function starting from an entry point
    fn scan_from(&self, start: usize, stack_size: i128) -> Result<RecognizedFunction, ParseError> {
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

            if let Ok((i1, i2)) = self.recognize_return(offset, stack_size) {
                returns.push(Span::new(i1.span.start, i2.span.end));
                instructions.push(i1);
                instructions.push(i2);
                continue;
            } else if let Ok((i1, i2, fc)) = self.recognize_function_call(offset) {
                queue.push(fc.return_address);
                instructions.push(i1);
                instructions.push(i2);
                function_calls.push(fc);
            } else {
                let instruction = NativeInstruction::parse(self.image(), offset)?;
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
        let span = Span::new(start, instructions.last().unwrap().span.end);

        // Convert memory references to pointers if they point within the function
        let mut t = |_: &mut (), op: &Operand| {
            if let Some(addr) = op.kind.get_memory() {
                if span.start <= addr && addr < span.end {
                    let mut r = *op;
                    r.kind = OperandKind::Pointer(addr);
                    return r;
                }
            }
            *op
        };

        for instruction in instructions.iter_mut() {
            *instruction = instruction.map_rw(&mut (), &mut t.clone(), &mut t);
        }

        Ok(RecognizedFunction {
            span,
            stack_size: stack_size as usize,
            instructions,
            return_span: returns.into_iter().next(),
            jump_targets,
            jump_instructions,
            function_calls,
            halts,
        })
    }
}
