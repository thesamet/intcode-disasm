use log::error;
use nom::{
    branch::alt,
    bytes::complete::{is_not, tag, take_while1},
    character::complete::{char, digit1, multispace1, satisfy, space0, space1},
    combinator::{eof, map, map_res, opt, recognize, value},
    multi::{many0, many1, separated_list1},
    sequence::{delimited, pair, preceded, terminated},
    IResult, Parser,
};
use std::collections::HashMap;

use super::v3::native::instruction::simplify_instruction; // Import from v3 native
use super::v3::native::{
    GenericNativeInstruction, NativeInstruction, NativeInstructionKind, Operand, OperandKind,
};
use super::{v2::Span, v3::NativeInstructionId};

type DebugMarker = Option<char>;

// Intermediate types used during parsing before full resolution
#[derive(Debug, Clone, PartialEq, Eq)]
enum UnresolvedArgument {
    Label {
        name: String,
        debug_marker: DebugMarker,
    },
    Pointer {
        name: String,
        debug_marker: DebugMarker,
    },
    PointerDeref {
        name: String,
        debug_marker: DebugMarker,
    },
    Resolved {
        op: Operand,
    },
}

impl From<UnresolvedArgument> for Operand {
    fn from(arg: UnresolvedArgument) -> Self {
        match arg {
            UnresolvedArgument::Resolved { op, .. } => op,
            _ => panic!("UnresolvedArgument must be resolved before conversion to Operand"),
        }
    }
}

// Helper to get the expected size of an instruction kind for offset calculation
// Note: Relies on the structure before simplification (e.g., Assign is size 4 because it becomes Add)
pub fn instruction_kind_size<T>(kind: &NativeInstructionKind<T>) -> usize {
    match kind {
        NativeInstructionKind::Add(..)
        | NativeInstructionKind::Mul(..)
        | NativeInstructionKind::LessThan(..)
        | NativeInstructionKind::Equals(..)
        | NativeInstructionKind::Assign(..) => 4,

        NativeInstructionKind::JumpIfTrue(..)
        | NativeInstructionKind::JumpIfFalse(..)
        | NativeInstructionKind::Goto(..) => 3,

        NativeInstructionKind::Input(_)
        | NativeInstructionKind::Output(_)
        | NativeInstructionKind::AdjustRelativeBase(_) => 2,

        NativeInstructionKind::Halt => 1,
        NativeInstructionKind::Data(v) => v.len(),
    }
}

// Parse a signed i128
fn parse_i128(input: &str) -> IResult<&str, i128> {
    map_res(recognize(pair(opt(char('-')), digit1)), |s: &str| {
        s.parse::<i128>()
    })
    .parse(input)
}

fn identifier(input: &str) -> IResult<&str, &str> {
    take_while1(|c: char| c.is_alphanumeric() || c == '_').parse(input)
}
// Parse arguments
fn parse_memory(input: &str, debug_marker: DebugMarker) -> IResult<&str, UnresolvedArgument> {
    alt((
        map(delimited(char('['), parse_i128, char(']')), |a| {
            // Temporarily create OperandKind, offset is unknown here (placeholder 0)
            UnresolvedArgument::Resolved {
                op: Operand {
                    kind: OperandKind::Memory(a as usize),
                    offset: 0,
                    debug_marker,
                },
            }
        }),
        (tag("*"), identifier).map(|(_, ident)| UnresolvedArgument::PointerDeref {
            name: ident.to_string(),
            debug_marker,
        }),
        identifier.map(|ident| UnresolvedArgument::Pointer {
            name: ident.to_string(),
            debug_marker,
        }),
    ))
    .parse(input)
}

// Parses into temporary Arg enum first
fn parse_immediate(input: &str) -> IResult<&str, OperandKind> {
    map(parse_i128, OperandKind::Immediate).parse(input)
}

// Parses into temporary Arg enum first
fn parse_relative_mem(input: &str) -> IResult<&str, OperandKind> {
    alt((
        map(
            delimited(tag("[R+"), parse_i128, char(']')),
            OperandKind::RelativeMemory,
        ),
        map(delimited(tag("[R-"), parse_i128, char(']')), |val| {
            OperandKind::RelativeMemory(-val)
        }),
        value(OperandKind::RelativeMemory(0), tag("[R]")),
    ))
    .parse(input)
}

fn parse_label_ref(input: &str, debug_marker: DebugMarker) -> IResult<&str, UnresolvedArgument> {
    map(preceded(char('@'), identifier), |s: &str| {
        UnresolvedArgument::Label {
            name: s.to_string(),
            debug_marker,
        }
    })
    .parse(input)
}
fn debug_marker(input: &str) -> IResult<&str, char> {
    (tag("'"), satisfy(|c| c.is_alphabetic()), space0)
        .map(|(_, c, _)| c)
        .parse(input)
}

fn parse_argument(input: &str) -> IResult<&str, UnresolvedArgument> {
    alt((
        pair(
            opt(debug_marker),
            alt((parse_relative_mem, parse_immediate)),
        )
        .map(|(debug_marker, kind)| {
            // Resolve Arg -> OperandKind here, offset still unknown (0 placeholder)
            UnresolvedArgument::Resolved {
                op: Operand {
                    kind,
                    offset: 0, // Placeholder, will be filled in later
                    debug_marker,
                },
            }
        }),
        opt(debug_marker)
            .flat_map(|debug_marker| move |input| parse_label_ref(input, debug_marker)),
        opt(debug_marker).flat_map(|debug_marker| move |input| parse_memory(input, debug_marker)),
    ))
    .parse(input)
}

// Parse instructions returning InstructionKind<UnresolvedArgument>
fn parse_add(input: &str) -> IResult<&str, NativeInstructionKind<UnresolvedArgument>> {
    map(
        (
            parse_argument,
            space0,
            char('='),
            space0,
            parse_argument,
            space0,
            char('+'),
            space0,
            parse_argument,
        ),
        |(c, _, _, _, a, _, _, _, b)| NativeInstructionKind::Add(a, b, c),
    )
    .parse(input)
}

fn parse_mul(input: &str) -> IResult<&str, NativeInstructionKind<UnresolvedArgument>> {
    map(
        (
            parse_argument,
            space0,
            char('='),
            space0,
            parse_argument,
            space0,
            char('*'),
            space0,
            parse_argument,
        ),
        |(c, _, _, _, a, _, _, _, b)| NativeInstructionKind::Mul(a, b, c),
    )
    .parse(input)
}

fn parse_assign(input: &str) -> IResult<&str, NativeInstructionKind<UnresolvedArgument>> {
    map(
        (parse_argument, space0, char('='), space0, parse_argument),
        |(c, _, _, _, a)| NativeInstructionKind::Assign(c, a),
    )
    .parse(input)
}

fn parse_input(input: &str) -> IResult<&str, NativeInstructionKind<UnresolvedArgument>> {
    map((tag("INPUT"), space1, parse_argument), |(_, _, a)| {
        NativeInstructionKind::Input(a)
    })
    .parse(input)
}

fn parse_output(input: &str) -> IResult<&str, NativeInstructionKind<UnresolvedArgument>> {
    alt((
        map((tag("output"), space1, parse_argument), |(_, _, a)| {
            NativeInstructionKind::Output(a)
        }),
        map(
            delimited(tag("output("), parse_argument, char(')')),
            NativeInstructionKind::Output,
        ),
    ))
    .parse(input)
}

fn parse_if_goto(input: &str) -> IResult<&str, NativeInstructionKind<UnresolvedArgument>> {
    map(
        (
            tag("if"),
            space1,
            parse_argument,
            space1,
            tag("goto"),
            space1,
            parse_argument,
        ),
        |(_, _, a, _, _, _, b)| NativeInstructionKind::JumpIfTrue(a, b),
    )
    .parse(input)
}

fn parse_if_not_goto(input: &str) -> IResult<&str, NativeInstructionKind<UnresolvedArgument>> {
    map(
        (
            tag("if"),
            space1,
            char('!'),
            parse_argument,
            space1,
            tag("goto"),
            space1,
            parse_argument,
        ),
        |(_, _, _, a, _, _, _, b)| NativeInstructionKind::JumpIfFalse(a, b),
    )
    .parse(input)
}

fn parse_goto(input: &str) -> IResult<&str, NativeInstructionKind<UnresolvedArgument>> {
    map(preceded(pair(tag("goto"), space1), parse_argument), |a| {
        NativeInstructionKind::Goto(a)
    })
    .parse(input)
}

fn parse_less_than(input: &str) -> IResult<&str, NativeInstructionKind<UnresolvedArgument>> {
    map(
        (
            parse_argument,
            space0,
            char('='),
            space0,
            parse_argument,
            space0,
            char('<'),
            space0,
            parse_argument,
        ),
        |(c, _, _, _, a, _, _, _, b)| NativeInstructionKind::LessThan(a, b, c),
    )
    .parse(input)
}

fn parse_equals(input: &str) -> IResult<&str, NativeInstructionKind<UnresolvedArgument>> {
    map(
        (
            parse_argument,
            space0,
            char('='),
            space0,
            parse_argument,
            space0,
            tag("=="),
            space0,
            parse_argument,
        ),
        |(c, _, _, _, a, _, _, _, b)| NativeInstructionKind::Equals(a, b, c),
    )
    .parse(input)
}

fn parse_adjust_r(input: &str) -> IResult<&str, NativeInstructionKind<UnresolvedArgument>> {
    alt((
        map(
            (tag("R"), space0, tag("+="), space0, parse_argument),
            |(_, _, _, _, a)| NativeInstructionKind::AdjustRelativeBase(a),
        ),
        map(
            (tag("R"), space0, tag("-="), space0, parse_argument),
            |(_, _, _, _, a)| {
                // Need to negate the argument for subtract
                match a {
                    UnresolvedArgument::Resolved{op: Operand {
                        kind: OperandKind::Immediate(val),
                        offset: _, // Offset doesn't matter for this transformation
                        debug_marker,
                    } } => NativeInstructionKind::AdjustRelativeBase(UnresolvedArgument::Resolved{op:
                         // Create a resolved Operand directly
                        Operand { kind: OperandKind::Immediate(-val), offset: 0, debug_marker }
                    }),
                    // Handle Label case if R -= @label is valid (likely not)
                    // Handle Pointer/PointerDeref if R -= ptr/ *ptr is valid (likely not)
                    _ => panic!("Invalid argument for R -= adjust register instruction: Must be immediate value"),
                }
            },
        ),
    ))
    .parse(input)
}

fn parse_halt(input: &str) -> IResult<&str, NativeInstructionKind<UnresolvedArgument>> {
    map(tag("halt"), |_| NativeInstructionKind::Halt).parse(input)
}

fn parse_data_values(input: &str) -> IResult<&str, Vec<i128>> {
    separated_list1(
        // Use list1 to require at least one data value
        delimited(space0, char(','), space0),
        parse_i128,
    )
    .parse(input)
}

fn parse_data(input: &str) -> IResult<&str, NativeInstructionKind<UnresolvedArgument>> {
    map(
        preceded(pair(tag("DATA"), space1), parse_data_values),
        NativeInstructionKind::Data,
    )
    .parse(input)
}

fn parse_instruction(input: &str) -> IResult<&str, NativeInstructionKind<UnresolvedArgument>> {
    alt((
        // Order matters: Match longer/more specific patterns first
        parse_add,
        parse_mul,
        parse_less_than,
        parse_equals,
        parse_assign, // Assign uses '=', must come after LT/EQ/ADD/MUL
        parse_input,
        parse_output,
        parse_if_goto, // Needs to come before goto
        parse_if_not_goto,
        parse_goto,
        parse_adjust_r,
        parse_halt,
        parse_data,
    ))
    .parse(input)
}

// Parse a label definition
fn parse_label_def(input: &str) -> IResult<&str, String> {
    map(terminated(identifier, char(':')), String::from).parse(input)
}

// Define a parser that consumes whitespace (including newlines) or a full comment line.
fn ws_or_comment(input: &str) -> IResult<&str, ()> {
    let comment = value((), pair(tag(";"), is_not("\r\n")));
    /*
    use nom::multi::many0;
    // Define a comment parser that includes the trailing newline or EOF
    //    value((), many0(alt((value((), space0), comment)))).parse(input)
    comment.parse(input)
    */
    value((), many0(alt((value((), multispace1), comment)))).parse(input)
}

// Parse a line: optional label + optional instruction
fn parse_line(
    input: &str,
) -> IResult<&str, (Option<String>, NativeInstructionKind<UnresolvedArgument>)> {
    // Consume leading whitespace and any number of comment lines
    let (input, _) = ws_or_comment(input)?;
    let (input, label) = opt(parse_label_def).parse(input)?;
    // Consume whitespace/comments between label (if any) and instruction
    let (input, _) = ws_or_comment(input)?;
    let (input, instruction) = parse_instruction.parse(input)?;
    // Trailing whitespace/comments will be handled by the next call to parse_line or eof check

    Ok((input, (label, instruction)))
}

// This needs the instruction offset to calculate the operand offset.
fn resolve_argument(
    arg: &UnresolvedArgument,
    label_offsets: &HashMap<String, usize>,
    pointers: &HashMap<String, usize>,
) -> Result<Operand, String> {
    match arg {
        UnresolvedArgument::Label { name, debug_marker } => {
            if let Some(&target_addr) = label_offsets.get(name.as_str()) {
                // Use get with &str
                Ok(Operand {
                    kind: OperandKind::Immediate(target_addr as i128),
                    offset: 0,
                    debug_marker: *debug_marker,
                })
            } else {
                Err(format!("Undefined label: {name}"))
            }
        }
        UnresolvedArgument::PointerDeref { debug_marker, .. } => {
            // Resolve PointerDeref to Memory(0) as a placeholder for the value
            // that will be written into this operand's memory location by the pointer assignment.
            Ok(Operand {
                kind: OperandKind::Memory(0), // Placeholder
                offset: 0,
                debug_marker: *debug_marker,
            })
        }
        UnresolvedArgument::Pointer { name, debug_marker } => {
            // Resolve Pointer to Memory(target_argument_address)
            if let Some(&target_arg_addr) = pointers.get(name.as_str()) {
                // Use get with &str
                Ok(Operand {
                    kind: OperandKind::Pointer(target_arg_addr),
                    offset: 0,
                    debug_marker: *debug_marker,
                })
            } else {
                Err(format!("Undefined pointer: {name}"))
            }
        }
        UnresolvedArgument::Resolved { op } => {
            // Already resolved during parsing (e.g., immediate, direct mem/rel), just update offset
            Ok(*op)
        }
    }
}

// Main parser function
pub fn parse_program(
    input: &str,
) -> Result<Vec<(usize, NativeInstruction)>, nom::Err<nom::error::Error<&str>>> {
    let (input, lines) = many1(parse_line).parse(input)?;
    let (input, _) = ws_or_comment(input)?;
    let (_, _) = eof.parse(input)?;

    let mut label_offsets = HashMap::new();
    let mut pointers = HashMap::new();
    let mut current_offset = 0;
    let mut intermediate_instructions: Vec<(usize, NativeInstructionKind<UnresolvedArgument>)> =
        Vec::new();

    // First pass: Collect labels and pointer definitions
    for (label, instruction) in &lines {
        if let Some(label) = label {
            label_offsets.insert(label.clone(), current_offset);
        }

        // Store pointer definitions: map name to the memory address *of the argument*
        // that will be modified by the pointer assignment.
        if !matches!(instruction, NativeInstructionKind::Data(_)) {
            for i in 0..=2 {
                if let Some(UnresolvedArgument::PointerDeref { name, .. }) =
                    instruction.operand_at(i)
                {
                    pointers.insert(name.clone(), current_offset + i + 1);
                }
            }
        }
        intermediate_instructions.push((current_offset, instruction.clone()));
        current_offset += instruction_kind_size(instruction);
    }

    // Second pass: resolve labels/pointers and create final instructions
    let resolved_instructions = intermediate_instructions
        .into_iter()
        .map(|(offset, instr_kind)| {
            // Create a temporary GenericInstruction to use map_rw_result
            // Span and ID are temporary here, will be set correctly on the final instruction
            let temp_instr = GenericNativeInstruction {
                id: NativeInstructionId::from(offset), // Use offset for temp ID
                span: Span::new(offset, offset + instruction_kind_size(&instr_kind)), // Temp span
                kind: instr_kind,
            };

            // Use map_rw_result for resolution
            let mut instruction = temp_instr.map_rw_result(
                &mut (&label_offsets, &pointers), // Context tuple
                &mut |ctx, arg| {
                    // map_read
                    let (lbl_offs, ptrs) = ctx;
                    // Determine logical arg index for read operands
                    // This is complex because map_rw doesn't provide index easily.
                    // We might need to resolve manually outside map_rw_result or enhance it.
                    // For now, let's assume index calculation is possible or done manually below.
                    // Placeholder: Assuming index 0 for simplicity here, needs proper logic.
                    resolve_argument(arg, lbl_offs, ptrs)
                    // Needs correct index
                },
                &mut |ctx, arg| {
                    // map_write
                    let (lbl_offs, ptrs) = ctx;
                    // Placeholder: Assuming index based on instruction type for writes.
                    resolve_argument(arg, lbl_offs, ptrs)
                    // Needs correct index
                },
            )?;
            for i in 0..=2 {
                let mut op = instruction.kind.operand_at_mut(i);
                if let Some(ref mut op) = op {
                    op.offset = offset + i + 1;
                }
            }

            instruction.kind = simplify_instruction(instruction.kind);

            Ok((offset, instruction))
        })
        .collect::<Result<Vec<(usize, NativeInstruction)>, String>>()
        .map_err(|t| {
            // Convert String error to nom::Err
            error!("Parsing error: {}", t);
            nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Verify))
            // Pass input string slice
        })?;

    Ok(resolved_instructions)
}

pub fn compile(code: &str) -> Vec<i128> {
    let program = parse_program(code).unwrap();
    let mut out = vec![];
    for (_, instruction) in program {
        // --- Serialization Logic ---
        let base_opcode = instruction.opcode().as_i128();
        let mut args_to_serialize: Vec<Operand> = vec![];
        let mut modes: Vec<i128> = vec![];

        match &instruction.kind {
            NativeInstructionKind::Data(v) => {
                out.extend(v);
                continue; // Skip normal serialization
            }
            NativeInstructionKind::Halt => { /* No args */ }
            NativeInstructionKind::Add(a, b, c) => {
                args_to_serialize = vec![*a, *b, *c];
            }
            NativeInstructionKind::Mul(a, b, c) => {
                args_to_serialize = vec![*a, *b, *c];
            }
            NativeInstructionKind::Input(a) => {
                args_to_serialize = vec![*a];
            }
            NativeInstructionKind::Output(a) => {
                args_to_serialize = vec![*a];
            }
            NativeInstructionKind::JumpIfTrue(a, b) => {
                args_to_serialize = vec![*a, *b];
            }
            NativeInstructionKind::JumpIfFalse(a, b) => {
                args_to_serialize = vec![*a, *b];
            }
            NativeInstructionKind::LessThan(a, b, c) => {
                args_to_serialize = vec![*a, *b, *c];
            }
            NativeInstructionKind::Equals(a, b, c) => {
                args_to_serialize = vec![*a, *b, *c];
            }
            NativeInstructionKind::AdjustRelativeBase(a) => {
                args_to_serialize = vec![*a];
            }
            // Synthetic instructions serialized as underlying Intcode
            NativeInstructionKind::Goto(target) => {
                // Need an immediate '1' operand first
                let cond_operand = Operand {
                    kind: OperandKind::Immediate(1),
                    offset: 0,
                    debug_marker: None,
                }; // Offset doesn't matter for serialization value
                args_to_serialize = vec![cond_operand, *target];
                // base_opcode is already 5 via instruction.opcode()
            }
            NativeInstructionKind::Assign(target, source) => {
                // Need an immediate '0' operand
                let zero_operand = Operand {
                    kind: OperandKind::Immediate(0),
                    offset: 0,
                    debug_marker: None,
                };
                // Order for underlying Add: source, zero, target
                args_to_serialize = vec![*source, zero_operand, *target];
            }
        }

        let mut mode_flags = 0i128;
        let mut marker_flags = 0i128;

        for (i, operand) in args_to_serialize.iter().enumerate() {
            let mode = match operand.kind {
                OperandKind::Memory(_) | OperandKind::Deref(_) | OperandKind::Pointer(_) => 0, // Treat Pointers and Deref as Memory for mode
                OperandKind::Immediate(_) => 1,
                OperandKind::RelativeMemory(_) => 2,
            };
            modes.push(mode);
            mode_flags += mode * 10i128.pow((i as u32) + 2);

            if let Some(marker) = operand.debug_marker {
                // Ensure marker value is within u8 range if necessary
                let marker_val = marker as i128;
                if marker_val > 0 && marker_val <= 255 {
                    // Correct calculation: (marker value * 2^(8*i)) * 100000
                    marker_flags += (marker_val << (8 * i)) * 100000;
                }
            }
        }

        out.push(base_opcode + mode_flags + marker_flags);

        for operand in args_to_serialize {
            let value = match operand.kind {
                OperandKind::Memory(addr) | OperandKind::Pointer(addr) => addr as i128,
                OperandKind::Immediate(val) => val,
                OperandKind::RelativeMemory(offset) => offset,
                // Deref(offset) refers to the *location* of the operand, not its value yet.
                // When serializing an instruction like `[R+1] = *ptr`, the `*ptr` operand
                // (which resolved to Memory(0)) should serialize as 0 initially.
                // The preceding `ptr = address_of_arg` instruction handles the modification.
                OperandKind::Deref(_) => 0,
            };
            out.push(value);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;

    use super::*;
    use crate::disasm::v3::native::{NativeInstructionKind, OperandKind};
    use pretty_assertions::assert_eq;

    // Helper function to parse a single instruction kind for testing
    fn parse_single_instruction_kind(input: &str) -> NativeInstructionKind<OperandKind> {
        let v = parse_program(input).unwrap();
        assert_eq!(v.len(), 1, "Expected single instruction for test");
        // Map Operand -> OperandKind for comparison in tests
        v[0].1
            .map_rw(&mut (), |_, op| op.kind, |_, op| op.kind)
            .kind
    }

    // Helper to parse a complete program and return just the instruction kinds
    fn parse_test_program_kinds(input: &str) -> Vec<NativeInstructionKind<OperandKind>> {
        let program = parse_program(input).unwrap();
        program
            .into_iter()
            .map(|(_, instr)| instr.map_rw(&mut (), |_, op| op.kind, |_, op| op.kind))
            .map(|i| i.kind)
            .collect_vec()
    }

    #[test]
    fn test_single_instructions() {
        // Test halt
        assert_eq!(
            parse_single_instruction_kind("halt"),
            NativeInstructionKind::Halt
        );

        // Test basic arithmetic with new syntax
        assert_eq!(
            parse_single_instruction_kind("[0] = 1 + 2"),
            NativeInstructionKind::Add(
                OperandKind::Immediate(1),
                OperandKind::Immediate(2),
                OperandKind::Memory(0)
            )
        );

        assert_eq!(
            parse_single_instruction_kind("[10] = [20] * 5"),
            NativeInstructionKind::Mul(
                OperandKind::Memory(20),
                OperandKind::Immediate(5),
                OperandKind::Memory(10)
            )
        );

        // Test assignment simplification
        assert_eq!(
            parse_single_instruction_kind("[10] = [20] + 0"),
            NativeInstructionKind::Assign(OperandKind::Memory(10), OperandKind::Memory(20)) // simplify applied
        );
        assert_eq!(
            parse_single_instruction_kind("[10] = 1 * [20]"),
            NativeInstructionKind::Assign(OperandKind::Memory(10), OperandKind::Memory(20)) // simplify applied
        );

        // Test INPUT/output
        assert_eq!(
            parse_single_instruction_kind("INPUT [0]"),
            NativeInstructionKind::Input(OperandKind::Memory(0))
        );

        assert_eq!(
            parse_single_instruction_kind("output 42"),
            NativeInstructionKind::Output(OperandKind::Immediate(42))
        );

        // Test the alternative output syntax
        assert_eq!(
            parse_single_instruction_kind("output(100)"),
            NativeInstructionKind::Output(OperandKind::Immediate(100))
        );

        // Test conditional jumps
        assert_eq!(
            parse_single_instruction_kind("if [0] goto 100"),
            NativeInstructionKind::JumpIfTrue(OperandKind::Memory(0), OperandKind::Immediate(100))
        );

        assert_eq!(
            parse_single_instruction_kind("if ![5] goto 200"),
            NativeInstructionKind::JumpIfFalse(OperandKind::Memory(5), OperandKind::Immediate(200))
        );

        // Test jump simplification
        assert_eq!(
            parse_single_instruction_kind("if 1 goto 100"), // Non-zero constant
            NativeInstructionKind::Goto(OperandKind::Immediate(100))  // simplify applied
        );
        assert_eq!(
            parse_single_instruction_kind("if 0 goto 100"), // Zero constant -> no jump
            NativeInstructionKind::JumpIfTrue(
                OperandKind::Immediate(0),
                OperandKind::Immediate(100)
            )  // Expected: Not simplified
        );
        assert_eq!(
            parse_single_instruction_kind("if !0 goto 100"), // Not zero constant
            NativeInstructionKind::Goto(OperandKind::Immediate(100))  // simplify applied
        );
        assert_eq!(
            parse_single_instruction_kind("if !1 goto 100"), // Not non-zero constant -> no jump
            NativeInstructionKind::JumpIfFalse(
                OperandKind::Immediate(1),
                OperandKind::Immediate(100)
            )  // Expected: Not simplified
        );

        // Test comparison operations
        assert_eq!(
            parse_single_instruction_kind("[0] = [1] < [2]"),
            NativeInstructionKind::LessThan(
                OperandKind::Memory(1),
                OperandKind::Memory(2),
                OperandKind::Memory(0)
            )
        );

        assert_eq!(
            parse_single_instruction_kind("[0] = [1] == [2]"),
            NativeInstructionKind::Equals(
                OperandKind::Memory(1),
                OperandKind::Memory(2),
                OperandKind::Memory(0)
            )
        );

        assert_eq!(
            parse_single_instruction_kind("[R-1] = [R-3] == [R-2]"),
            NativeInstructionKind::Equals(
                OperandKind::RelativeMemory(-3),
                OperandKind::RelativeMemory(-2),
                OperandKind::RelativeMemory(-1)
            )
        );

        // Test R adjustment
        assert_eq!(
            parse_single_instruction_kind("R += 10"),
            NativeInstructionKind::AdjustRelativeBase(OperandKind::Immediate(10))
        );

        assert_eq!(
            parse_single_instruction_kind("R -= 5"),
            NativeInstructionKind::AdjustRelativeBase(OperandKind::Immediate(-5)) // Check negation
        );

        // Test relative memory addressing
        assert_eq!(
            parse_single_instruction_kind("[0] = [R+5] + [R-3]"),
            NativeInstructionKind::Add(
                OperandKind::RelativeMemory(5),
                OperandKind::RelativeMemory(-3),
                OperandKind::Memory(0)
            )
        );
    }

    #[test]
    fn test_simple_program() {
        let program = "
            INPUT [0]
            INPUT [1]
            [2] = [0] + [1]
            output [2]
            halt
        ";

        let expected = vec![
            NativeInstructionKind::Input(OperandKind::Memory(0)),
            NativeInstructionKind::Input(OperandKind::Memory(1)),
            NativeInstructionKind::Add(
                OperandKind::Memory(0),
                OperandKind::Memory(1),
                OperandKind::Memory(2),
            ),
            NativeInstructionKind::Output(OperandKind::Memory(2)),
            NativeInstructionKind::Halt,
        ];

        assert_eq!(parse_test_program_kinds(program), expected);
    }

    #[test]
    fn test_program_with_labels() {
        let program = "
            INPUT [0]       ; Get a number          ; 0
            [1] = 1 + 0     ; Initialize counter    ; 2 -> Assign
            loop:           ;                       ; 6
                [2] = [1] * [0]  ; Multiply         ; 6
                output [2]  ; Output the result     ; 10
                [1] = [1] + 1    ; Increment counter; 12
                [3] = [1] < 5    ; Check if counter < 5 ; 16
                if [3] goto @loop  ; Loop if true   ; 20
            halt            ;                       ; 23
        ";

        let instructions = parse_test_program_kinds(program);

        // Offsets: INPUT=2, Assign=4, Mul=4, Output=2, Add=4, Lt=4, If=3, Halt=1
        // loop: starts at offset 6

        let expected = vec![
            NativeInstructionKind::Input(OperandKind::Memory(0)), // 0
            NativeInstructionKind::Assign(OperandKind::Memory(1), OperandKind::Immediate(1)), // 2
            NativeInstructionKind::Mul(
                OperandKind::Memory(1),
                OperandKind::Memory(0),
                OperandKind::Memory(2),
            ), // 6 (loop)
            NativeInstructionKind::Output(OperandKind::Memory(2)), // 10
            NativeInstructionKind::Add(
                OperandKind::Memory(1),
                OperandKind::Immediate(1),
                OperandKind::Memory(1),
            ), // 12
            NativeInstructionKind::LessThan(
                OperandKind::Memory(1),
                OperandKind::Immediate(5),
                OperandKind::Memory(3),
            ), // 16
            NativeInstructionKind::JumpIfTrue(OperandKind::Memory(3), OperandKind::Immediate(6)), // 20 -> jumps to 6
            NativeInstructionKind::Halt, // 23
        ];

        assert_eq!(instructions, expected);
    }

    #[test]
    fn test_complex_program() {
        let program = "
            ; Initialize variables
            [0] = 0 + 0    ; sum = 0                 ; 0 -> Assign
            [1] = 1 + 0    ; i = 1                   ; 4 -> Assign
            [10] = 10 + 0  ; limit = 10              ; 8 -> Assign

            ; Main loop to calculate sum of 1 to 10
            loop:          ;                         ; 12
                ; Check if i <= limit
                [2] = [1] < [10]     ; i < limit?    ; 12
                [3] = [1] == [10]    ; i == limit?   ; 16
                [4] = [2] + [3]      ; result of i <= limit ; 20

                ; If i > limit, exit loop
                if ![4] goto @done ;                 ; 24

                ; sum += i
                [0] = [0] + [1]    ;                 ; 27

                ; i++
                [1] = [1] + 1      ;                 ; 31

                ; Continue loop
                goto @loop         ;                 ; 35

            done:          ;                         ; 38
                ; Output final sum
                output [0]         ;                 ; 38
                halt               ;                 ; 40
        ";

        let instructions = parse_test_program_kinds(program);

        // Verify the program length
        assert_eq!(instructions.len(), 12);

        // Check key instructions (addresses calculated based on sizes)
        let expected = vec![
            NativeInstructionKind::Assign(OperandKind::Memory(0), OperandKind::Immediate(0)), // 0
            NativeInstructionKind::Assign(OperandKind::Memory(1), OperandKind::Immediate(1)), // 4
            NativeInstructionKind::Assign(OperandKind::Memory(10), OperandKind::Immediate(10)), // 8
            NativeInstructionKind::LessThan(
                OperandKind::Memory(1),
                OperandKind::Memory(10),
                OperandKind::Memory(2),
            ), // 12 (loop)
            NativeInstructionKind::Equals(
                OperandKind::Memory(1),
                OperandKind::Memory(10),
                OperandKind::Memory(3),
            ), // 16
            NativeInstructionKind::Add(
                OperandKind::Memory(2),
                OperandKind::Memory(3),
                OperandKind::Memory(4),
            ), // 20
            NativeInstructionKind::JumpIfFalse(OperandKind::Memory(4), OperandKind::Immediate(38)), // 24 -> jumps to done (38)
            NativeInstructionKind::Add(
                OperandKind::Memory(0),
                OperandKind::Memory(1),
                OperandKind::Memory(0),
            ), // 27
            NativeInstructionKind::Add(
                OperandKind::Memory(1),
                OperandKind::Immediate(1),
                OperandKind::Memory(1),
            ), // 31
            NativeInstructionKind::Goto(OperandKind::Immediate(12)), // 35 -> jumps to loop (12)
            NativeInstructionKind::Output(OperandKind::Memory(0)),   // 38 (done)
            NativeInstructionKind::Halt,                             // 40
        ];

        assert_eq!(instructions, expected);
    }

    #[test]
    fn test_nested_labels() {
        // Just checks parsing and length
        let program = "
            [0] = 0 + 0    ; result = 0
            [1] = 1 + 0    ; i = 1
            [2] = 5 + 0    ; max = 5
            outer_loop:
                [3] = [1] < [2]
                if ![3] goto @done
                [10] = 1 + 0    ; j = 1
                inner_loop:
                    [11] = [10] < [1]
                    if ![11] goto @inner_done
                    [20] = [1] * [10]
                    [0] = [0] + [20]
                    [10] = [10] + 1
                    goto @inner_loop
                inner_done:
                    [1] = [1] + 1
                    goto @outer_loop
            done:
                output [0]
                halt
        ";
        let instructions = parse_test_program_kinds(program);
        assert_eq!(instructions.len(), 16);
        assert_eq!(instructions.last().unwrap(), &NativeInstructionKind::Halt);
    }

    #[test]
    fn test_comments_and_whitespace() {
        let program = "
            ; This program calculates 5 + 7

            ; Initialize values
            [0] = 5 + 0    ; First value (Assign)

            ; Add second value
            [0] = [0] + 7  ; Add 7

            ; Output the result
            output [0]     ; Should be 12

            ; End program
            halt
        ";

        let expected = vec![
            NativeInstructionKind::Assign(OperandKind::Memory(0), OperandKind::Immediate(5)),
            NativeInstructionKind::Add(
                OperandKind::Memory(0),
                OperandKind::Immediate(7),
                OperandKind::Memory(0),
            ),
            NativeInstructionKind::Output(OperandKind::Memory(0)),
            NativeInstructionKind::Halt,
        ];

        assert_eq!(parse_test_program_kinds(program), expected);
    }
    #[test]
    fn test_label_position_in_args() {
        let program = "
            ; Test using labels in different positions
            start:             ; 0
                [0] = 1 + 0    ; 0 -> Assign
                [1] = 2 + 0    ; 4 -> Assign

                ; Label as condition argument for jump
                if @loop goto @done ; 8 -> If(@loop=11, @done=26)

            loop:              ; 11
                ; Label as second argument for arithmetic
                [2] = @loop + 10      ; 11 -> Add(Immediate(11), Immediate(10), Mem(2))

                ; Label in comparison
                [3] = 5 < @done       ; 15 -> Lt(Immediate(5), Immediate(26), Mem(3))

                ; Label as target for goto
                [4] = 100 + 200  ; 19 -> Add(...)
                goto @loop       ; 23 -> Goto(@loop=11)

            done:              ; 26
                output [0]       ; 26
                halt             ; 28
        ";

        let ops = parse_test_program_kinds(program);

        let expected = vec![
            NativeInstructionKind::Assign(OperandKind::Memory(0), OperandKind::Immediate(1)), // 0
            NativeInstructionKind::Assign(OperandKind::Memory(1), OperandKind::Immediate(2)), // 4
            NativeInstructionKind::Goto(OperandKind::Immediate(26)),                          // 8
            NativeInstructionKind::Add(
                OperandKind::Immediate(11),
                OperandKind::Immediate(10),
                OperandKind::Memory(2),
            ), // 11 (loop)
            NativeInstructionKind::LessThan(
                OperandKind::Immediate(5),
                OperandKind::Immediate(26),
                OperandKind::Memory(3),
            ), // 15
            NativeInstructionKind::Add(
                OperandKind::Immediate(100),
                OperandKind::Immediate(200),
                OperandKind::Memory(4),
            ), // 19
            NativeInstructionKind::Goto(OperandKind::Immediate(11)),                          // 23
            NativeInstructionKind::Output(OperandKind::Memory(0)), // 26 (done)
            NativeInstructionKind::Halt,                           // 28
        ];

        assert_eq!(ops, expected);
    }

    #[test]
    fn test_debug_marker() {
        let program = "
            'x [0] = 0 + 0    ; Assign: marker 'x on target (arg 2 of Add)
            [1] = 'y 10 + 0   ; Assign: marker 'y on source (arg 0 of Add)
            [2] = 0 + 'z 5    ; Add: marker 'z on arg 1
            'a ptr = 350      ; Assign: marker 'a on target '[<addr>]' (arg 2 of Add)
            [3] = 'b *ptr     ; Assign: marker 'b on source '*ptr' -> Mem(0) (arg 0 of Add)
        ";

        let instructions = parse_program(program).unwrap();
        let instructions = instructions.into_iter().map(|(_, inst)| inst).collect_vec();

        // Check first instruction: 'x [0] = 0 + 0 -> Assign([0], 0) -> Add(0, 0, [0])
        if let NativeInstructionKind::Assign(target, source) = &instructions[0].kind {
            assert_eq!(source.debug_marker, None); // Source 0 (arg 0)
            assert_eq!(target.debug_marker, Some('x')); // Target [0] (arg 2)
        } else {
            panic!("Expected Assign instruction 0");
        }

        // Check second instruction: [1] = 'y 10 + 0 -> Assign([1], 'y 10) -> Add('y 10, 0, [1])
        if let NativeInstructionKind::Assign(target, source) = &instructions[1].kind {
            assert_eq!(source.debug_marker, Some('y')); // Source 'y 10 (arg 0)
            assert_eq!(target.debug_marker, None); // Target [1] (arg 2)
        } else {
            panic!("Expected Assign instruction 1");
        }

        // Check third instruction: [2] = 0 + 'z 5
        if let NativeInstructionKind::Assign(arg0, arg1) = &instructions[2].kind {
            assert_eq!(arg0.debug_marker, None);
            assert_eq!(arg1.debug_marker, Some('z'));
        } else {
            panic!("Expected Add instruction 2");
        }

        // Next assign [3]=*ptr starts at 16. The *ptr operand is at 16+0+1=17 (using underlying Add indices).
        // So 'a ptr = 350' -> Assign(Mem(13), Imm(350)) -> Target Mem(17) gets marker 'a'.
        if let NativeInstructionKind::Assign(target, source) = &instructions[3].kind {
            assert!(
                matches!(target.kind, OperandKind::Pointer(17)),
                "Expected target to be Pointer(17), got {:?}",
                target.kind
            ); // Points to offset of *ptr arg
            assert_eq!(target.debug_marker, Some('a')); // Marker 'a' is on the target operand
            assert_eq!(source.debug_marker, None);
            assert!(
                matches!(source.kind, OperandKind::Immediate(350)),
                "Expected source to be Imm(350)"
            );
        } else {
            panic!("Expected Assign instruction 3");
        }

        // Check fifth instruction: [3] = 'b *ptr -> Assign([3], 'b Mem(0)) -> Add('b Mem(0), 0, [3])
        if let NativeInstructionKind::Assign(target, source) = &instructions[4].kind {
            assert_eq!(source.debug_marker, Some('b')); // Source '*ptr' (arg 0) has marker 'b'
            assert!(
                matches!(source.kind, OperandKind::Memory(0)),
                "Expected source kind Mem(0)"
            ); // *ptr resolves to Memory(0) placeholder
            assert_eq!(target.debug_marker, None); // Target [3] (arg 2)
            assert!(
                matches!(target.kind, OperandKind::Memory(3)),
                "Expected target kind Mem(3)"
            );
        } else {
            panic!("Expected Assign instruction 4");
        }

        // Check compiled markers
        let compiled = compile(program);
        // Inst 0: Assign [0] = 0 -> Add(Imm(0), Imm(0), Mem(0)) -> Opcode 1, modes 110 -> 1101. marker x on target (arg 2).
        // marker_flags = ('x' << 16) * 100000 = (120 << 16) * 100000 = 7864320 * 100000 = 786432000000
        assert_eq!(compiled[0], 786432001101); // 'x' on arg 2
                                               // Inst 1: Assign [1] = 10 -> Add(Imm(10), Imm(0), Mem(1)) -> Opcode 1, modes 110 -> 1101. marker y on source (arg 0).
                                               // marker_flags = ('y' << 0) * 100000 = 121 * 100000 = 12100000
        assert_eq!(compiled[4], 12101101); // 'y' on arg 0
                                           // Inst 2: Add(Imm(0), Imm(5), Mem(2)) -> Opcode 1, modes 110 -> 1101. marker z on arg 1.
                                           // marker_flags = ('z' << 8) * 100000 = (122 << 8) * 100000 = 31232 * 100000 = 3123200000
        assert_eq!(compiled[8], 12201101); // 'z' on arg 1
                                           // Inst 3: Assign(Mem(17), Imm(350)) -> Add(Imm(350), Imm(0), Mem(13)) -> Opcode 1, modes 110 -> 1101. marker a on target (arg 2).
                                           // marker_flags = ('a' << 16) * 100000 = (97 << 16) * 100000 = 6356992 * 100000 = 635699200000
        assert_eq!(compiled[12], 635699201101); // 'a' on arg 2
                                                // Inst 4: Assign(Mem(3), Mem(0)) -> Add(Mem(0), Imm(0), Mem(3)) -> Opcode 1, modes 010 -> 101. marker b on source (arg 0).
                                                // marker_flags = ('b' << 0) * 100000 = 98 * 100000 = 9800000
        assert_eq!(compiled[16], 9801001); // 'b' on arg 0
    }
    #[test]
    fn test_data_instruction() {
        let program = "DATA 10, 20, -30";
        let expected = NativeInstructionKind::Data(vec![10, 20, -30]);
        assert_eq!(parse_single_instruction_kind(program), expected);
    }

    #[test]
    fn test_program_with_data() {
        let program = "
            start:
                [0] = 1 + 2    ; Add: offset 0, size 4
                goto @data_section ; Goto: offset 4, size 3 (@data=8)
            halt ; Should not be reached ; Halt: offset 7, size 1

            data_section:      ; 8
                DATA 100, 200, 300 ; Data: offset 8, size 3
                output [0] ; Instruction after data ; Output: offset 11, size 2
                halt       ; Halt: offset 13, size 1
        ";

        let instructions = parse_test_program_kinds(program);

        let expected = vec![
            NativeInstructionKind::Add(
                OperandKind::Immediate(1),
                OperandKind::Immediate(2),
                OperandKind::Memory(0),
            ), // Offset 0
            NativeInstructionKind::Goto(OperandKind::Immediate(8)), // Offset 4
            NativeInstructionKind::Halt,                            // Offset 7 (unreachable)
            NativeInstructionKind::Data(vec![100, 200, 300]),       // Offset 8
            NativeInstructionKind::Output(OperandKind::Memory(0)),  // Offset 11
            NativeInstructionKind::Halt,                            // Offset 13
        ];

        assert_eq!(instructions, expected);
    }

    #[test]
    fn test_compile_with_data() {
        let program = "
            [0] = 1 + 2
            DATA 10, 20, 30
            halt
        ";
        // Add: 1, 1, 2, 0 -> Opcode 1, modes 110 -> 1101. Args: 1, 2, 0
        // Data: 10, 20, 30
        // Halt: 99
        let expected_binary = vec![1101, 1, 2, 0, 10, 20, 30, 99];
        let actual_binary = compile(program);
        assert_eq!(actual_binary, expected_binary);
    }

    #[test]
    fn test_compile_program_starts_with_data() {
        let program = "
            DATA 5, 6, 7
            halt
        ";
        let expected_binary = vec![5, 6, 7, 99];
        let actual_binary = compile(program);
        assert_eq!(actual_binary, expected_binary);
    }

    #[test]
    fn test_consecutive_comments() {
        let program = "
            ; comment 1
            ; comment 2
            start:          ; label def
                ; comment 3
                ; comment 4
                [0] = 1 + 2 ; instruction
                ; comment 5
                ; comment 6
            halt
            ; comment 7 at end
            ; comment 8 at end
        ";
        let instructions = parse_test_program_kinds(program);
        assert_eq!(instructions.len(), 2);
        assert!(matches!(
            instructions[0],
            NativeInstructionKind::Add(_, _, _)
        ));
        assert!(matches!(instructions[1], NativeInstructionKind::Halt));
    }
}
