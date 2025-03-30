use nom::{
    branch::alt,
    bytes::complete::{is_not, tag, take_while1},
    character::complete::{self, char, digit1, multispace0, space0, space1},
    combinator::{eof, map, map_res, opt, recognize, value},
    multi::{many1, separated_list0},
    sequence::{delimited, pair, preceded, terminated},
    IResult, Parser,
};
use std::collections::HashMap;

use super::low_ir::{Arg, ArgBase, GenericInstruction, PositionalArg};

type DebugMarker = Option<char>;

enum UnresolvedArgument {
    Label(String, DebugMarker),
    Pointer(String, DebugMarker),
    PointerDeref(String, DebugMarker),
    Resolved(SourceArgument),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceArgument {
    pub arg: Arg,
    pub debug_marker: DebugMarker,
}

impl SourceArgument {
    pub fn new(arg: Arg, debug_marker: DebugMarker) -> Self {
        SourceArgument { arg, debug_marker }
    }
}

impl SerializableArgument for SourceArgument {
    fn mode(&self) -> i128 {
        self.arg.mode()
    }

    fn serialize(&self, out: &mut Vec<i128>) {
        self.arg.serialize(out);
    }
}

pub trait SerializableArgument {
    fn mode(&self) -> i128;
    fn serialize(&self, out: &mut Vec<i128>);
}

impl SerializableArgument for Arg {
    fn mode(&self) -> i128 {
        match &self {
            Arg::Mem(_) | Arg::Deref(_) => 0,
            Arg::Value(_) => 1,
            Arg::RelativeMem(_) => 2,
        }
    }

    fn serialize(&self, out: &mut Vec<i128>) {
        let v = match self {
            Arg::Mem(addr) => *addr as i128,
            Arg::Value(val) => *val,
            Arg::RelativeMem(addr) => *addr as i128,
            Arg::Deref(addr) => *addr as i128,
        };
        out.push(v);
    }
}

impl ArgBase for SourceArgument {
    fn value(&self) -> Option<i128> {
        self.arg.value()
    }

    fn relative_mem(&self) -> Option<i128> {
        self.arg.relative_mem()
    }

    fn as_arg(&self) -> Arg {
        self.arg
    }
}

pub trait SerializableInstruction<ArgType> {
    fn serialize(&self, out: &mut Vec<i128>);
}

impl SerializableInstruction<SourceArgument> for GenericInstruction<SourceArgument> {
    fn serialize(&self, out: &mut Vec<i128>) {
        let opcode = match self {
            GenericInstruction::Add(_, _, _) | GenericInstruction::Assign(..) => 1,
            GenericInstruction::Mul(_, _, _) => 2,
            GenericInstruction::Input(_) => 3,
            GenericInstruction::Output(_) => 4,
            GenericInstruction::JumpIf(_, true, _) | GenericInstruction::Goto(_) => 5,
            GenericInstruction::JumpIf(_, false, _) => 6,
            GenericInstruction::LessThan(_, _, _) => 7,
            GenericInstruction::Equals(_, _, _) => 8,
            GenericInstruction::AdjustRelativeBase(_) => 9,
            GenericInstruction::Halt => 99,
            GenericInstruction::Data(_) => unreachable!(),
            GenericInstruction::Phi(_, _) => unreachable!(),
        } as i128;
        let mode = (0..=2)
            .map(|i| {
                self.arg_at(i)
                    .map(|a| {
                        let (mode, debug_marker) = match a {
                            PositionalArg::Arg(arg) => {
                                let debug_marker = arg
                                    .debug_marker
                                    .map(|c| (c as i128) << (8 * i))
                                    .unwrap_or_default()
                                    * 100000;
                                (arg.mode(), debug_marker)
                            }
                            PositionalArg::Immediate(v) => (1, 0),
                        };
                        mode * 10i128.pow((i as u32) + 2) + debug_marker
                    })
                    .unwrap_or_default()
            })
            .sum::<i128>();
        out.push(opcode + mode);
        for i in 0..3 {
            match self.arg_at(i) {
                Some(PositionalArg::Arg(a)) => a.serialize(out),
                Some(PositionalArg::Immediate(v)) => out.push(v as i128),
                None => {}
            };
        }
    }
}

type Instruction = GenericInstruction<UnresolvedArgument>;

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
            UnresolvedArgument::Resolved(SourceArgument::new(Arg::Mem(a), debug_marker))
        }),
        (tag("*"), identifier)
            .map(|(_, ident)| UnresolvedArgument::PointerDeref(ident.to_string(), debug_marker)),
        identifier.map(|ident| UnresolvedArgument::Pointer(ident.to_string(), debug_marker)),
    ))
    .parse(input)
}

fn parse_immediate(input: &str) -> IResult<&str, Arg> {
    map(parse_i128, Arg::Value).parse(input)
}

fn parse_relative_mem(input: &str) -> IResult<&str, Arg> {
    alt((
        map(
            delimited(tag("[R+"), parse_i128, char(']')),
            Arg::RelativeMem,
        ),
        map(delimited(tag("[R-"), parse_i128, char(']')), |val| {
            Arg::RelativeMem(-val)
        }),
        value(Arg::RelativeMem(0), tag("[R]")),
    ))
    .parse(input)
}

fn parse_label_ref(input: &str, debug_marker: DebugMarker) -> IResult<&str, UnresolvedArgument> {
    map(preceded(char('@'), identifier), |s: &str| {
        UnresolvedArgument::Label(s.to_string(), debug_marker)
    })
    .parse(input)
}
fn debug_marker(input: &str) -> IResult<&str, char> {
    (tag("'"), complete::satisfy(|c| c.is_alphabetic()), space0)
        .map(|(_, c, _)| c)
        .parse(input)
}

fn parse_argument(input: &str) -> IResult<&str, UnresolvedArgument> {
    alt((
        pair(
            opt(debug_marker),
            alt((parse_relative_mem, parse_immediate)),
        )
        .map(|(debug_marker, arg)| {
            UnresolvedArgument::Resolved(SourceArgument::new(arg, debug_marker))
        }),
        opt(debug_marker)
            .flat_map(|debug_marker| move |input| parse_label_ref(input, debug_marker)),
        opt(debug_marker).flat_map(|debug_marker| move |input| parse_memory(input, debug_marker)),
    ))
    .parse(input)
}

// Parse instructions
fn parse_add(input: &str) -> IResult<&str, Instruction> {
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
        |(c, _, _, _, a, _, _, _, b)| Instruction::Add(a, b, c),
    )
    .parse(input)
}

fn parse_mul(input: &str) -> IResult<&str, Instruction> {
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
        |(c, _, _, _, a, _, _, _, b)| Instruction::Mul(a, b, c),
    )
    .parse(input)
}

fn parse_assign(input: &str) -> IResult<&str, Instruction> {
    map(
        (parse_argument, space0, char('='), space0, parse_argument),
        |(c, _, _, _, a)| Instruction::Assign(c, a),
    )
    .parse(input)
}

fn parse_input(input: &str) -> IResult<&str, Instruction> {
    map((tag("INPUT"), space1, parse_argument), |(_, _, a)| {
        Instruction::Input(a)
    })
    .parse(input)
}

fn parse_output(input: &str) -> IResult<&str, Instruction> {
    alt((
        map((tag("output"), space1, parse_argument), |(_, _, a)| {
            Instruction::Output(a)
        }),
        map(
            delimited(tag("output("), parse_argument, char(')')),
            Instruction::Output,
        ),
    ))
    .parse(input)
}

fn parse_if_goto(input: &str) -> IResult<&str, Instruction> {
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
        |(_, _, a, _, _, _, b)| Instruction::JumpIf(a, true, b),
    )
    .parse(input)
}

fn parse_if_not_goto(input: &str) -> IResult<&str, Instruction> {
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
        |(_, _, _, a, _, _, _, b)| Instruction::JumpIf(a, false, b),
    )
    .parse(input)
}

fn parse_goto(input: &str) -> IResult<&str, Instruction> {
    map(preceded(pair(tag("goto"), space1), parse_argument), |a| {
        Instruction::Goto(a)
    })
    .parse(input)
}

fn parse_less_than(input: &str) -> IResult<&str, Instruction> {
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
        |(c, _, _, _, a, _, _, _, b)| Instruction::LessThan(a, b, c),
    )
    .parse(input)
}

fn parse_equals(input: &str) -> IResult<&str, Instruction> {
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
        |(c, _, _, _, a, _, _, _, b)| Instruction::Equals(a, b, c),
    )
    .parse(input)
}

fn parse_adjust_r(input: &str) -> IResult<&str, Instruction> {
    alt((
        map(
            (tag("R"), space0, tag("+="), space0, parse_argument),
            |(_, _, _, _, a)| Instruction::AdjustRelativeBase(a),
        ),
        map(
            (tag("R"), space0, tag("-="), space0, parse_argument),
            |(_, _, _, _, a)| {
                // Need to negate the argument for subtract
                match a {
                    UnresolvedArgument::Resolved(SourceArgument {
                        arg: Arg::Value(val),
                        debug_marker,
                    }) => Instruction::AdjustRelativeBase(UnresolvedArgument::Resolved(
                        SourceArgument::new(Arg::Value(-val), debug_marker),
                    )),
                    _ => panic!("Invalid argument for adjust register instruction"),
                }
            },
        ),
    ))
    .parse(input)
}

fn parse_halt(input: &str) -> IResult<&str, Instruction> {
    map(tag("halt"), |_| Instruction::Halt).parse(input)
}

fn parse_instruction(input: &str) -> IResult<&str, Instruction> {
    alt((
        parse_add,
        parse_mul,
        parse_input,
        parse_output,
        parse_if_goto,
        parse_if_not_goto,
        parse_goto,
        parse_less_than,
        parse_equals,
        parse_adjust_r,
        parse_assign,
        parse_halt,
    ))
    .parse(input)
}

// Parse a label definition
fn parse_label_def(input: &str) -> IResult<&str, String> {
    map(terminated(identifier, char(':')), String::from).parse(input)
}

fn comment(input: &str) -> IResult<&str, ()> {
    value(
        (), // Output is thrown away.
        pair(tag(";"), is_not("\n\r")),
    )
    .parse(input)
}

// Parse a line: optional label + optional instruction
fn parse_line(input: &str) -> IResult<&str, (Option<String>, Instruction)> {
    let (input, _) = multispace0(input)?;
    let (input, _) = separated_list0(char('\n'), comment).parse(input)?;
    let (input, _) = multispace0(input)?;
    let (input, label) = opt(parse_label_def).parse(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = separated_list0(char('\n'), comment).parse(input)?;
    let (input, _) = multispace0(input)?;
    let (input, instruction) = parse_instruction.parse(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = separated_list0(char('\n'), comment).parse(input)?;
    let (input, _) = multispace0(input)?;

    Ok((input, (label, instruction)))
}
//
// Main parser function
pub fn parse_program(
    input: &str,
) -> Result<Vec<(usize, GenericInstruction<SourceArgument>)>, nom::Err<nom::error::Error<&str>>> {
    let (input, lines) = many1(parse_line).parse(input)?;
    let (_, _) = eof.parse(input)?;

    // First pass: collect labels and their offsets
    let mut label_offsets = HashMap::new();
    let mut pointers = HashMap::new();
    let mut current_offset = 0;
    let mut instructions = Vec::new();

    for (label, instruction) in &lines {
        if let Some(label) = label {
            label_offsets.insert(label.clone(), current_offset);
        }
        for i in 0..=2 {
            match instruction.arg_at(i) {
                Some(PositionalArg::Arg(UnresolvedArgument::PointerDeref(name, debug_marker))) => {
                    pointers.insert(name.clone(), current_offset + i + 1);
                }
                Some(_) | None => {}
            }
        }

        instructions.push((current_offset, instruction));
        current_offset += instruction.size();
    }

    // Second pass: resolve labels to offsets
    let resolved_instructions = instructions
        .into_iter()
        .map(|(offset, instr)| {
            (instr.map_result(&mut (), |_, arg| match arg {
                UnresolvedArgument::Label(label, debug_marker) => {
                    if let Some(&target) = label_offsets.get(label) {
                        Ok(SourceArgument::new(
                            Arg::Value(target as i128),
                            *debug_marker,
                        ))
                    } else {
                        Err(format!("Undefined label: {}", label))
                    }
                }
                UnresolvedArgument::PointerDeref(_, debug_marker) => {
                    Ok(SourceArgument::new(Arg::Mem(0), *debug_marker))
                }
                UnresolvedArgument::Pointer(name, debug_marker) => {
                    if let Some(&target) = pointers.get(name) {
                        Ok(SourceArgument::new(Arg::Mem(target as i128), *debug_marker))
                    } else {
                        Err(format!("Undefined pointer: {}", name))
                    }
                }
                UnresolvedArgument::Resolved(arg) => Ok(arg.clone()),
            }))
            .map(|arg| (offset, arg))
        })
        .collect::<Result<Vec<(usize, GenericInstruction<SourceArgument>)>, String>>()
        .map_err(|_| {
            nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))
        })?;

    Ok(resolved_instructions)
}

#[cfg(test)]
pub fn compile(code: &str) -> Vec<i128> {
    let program = parse_program(code).unwrap();
    let mut out = vec![];
    for inst in program {
        inst.1.serialize(&mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;

    use super::*;

    type Instruction = GenericInstruction<Arg>;

    // Helper function to parse a single instruction
    fn parse_single_instruction(input: &str) -> Instruction {
        let v = parse_program(input).unwrap();
        v[0].1.map(|arg| arg.arg.clone())
    }

    // Helper to parse a complete program and return just the instructions
    fn parse_test_program(input: &str) -> Vec<Instruction> {
        let program = parse_program(input).unwrap();
        program
            .into_iter()
            .map(|(_, instr)| instr.map(|arg| arg.arg.clone()))
            .collect_vec()
    }

    #[test]
    fn test_single_instructions() {
        // Test halt
        assert_eq!(parse_single_instruction("halt"), Instruction::Halt);

        // Test basic arithmetic with new syntax
        assert_eq!(
            parse_single_instruction("[0] = 1 + 2"),
            Instruction::Add(Arg::Value(1), Arg::Value(2), Arg::Mem(0))
        );

        assert_eq!(
            parse_single_instruction("[10] = [20] * 5"),
            Instruction::Mul(Arg::Mem(20), Arg::Value(5), Arg::Mem(10))
        );

        // Test INPUT/output
        assert_eq!(
            parse_single_instruction("INPUT [0]"),
            Instruction::Input(Arg::Mem(0))
        );

        assert_eq!(
            parse_single_instruction("output 42"),
            Instruction::Output(Arg::Value(42))
        );

        // Test the alternative output syntax
        assert_eq!(
            parse_single_instruction("output(100)"),
            Instruction::Output(Arg::Value(100))
        );

        // Test conditional jumps
        assert_eq!(
            parse_single_instruction("if [0] goto 100"),
            Instruction::JumpIf(Arg::Mem(0), true, Arg::Value(100))
        );

        assert_eq!(
            parse_single_instruction("if ![5] goto 200"),
            Instruction::JumpIf(Arg::Mem(5), false, Arg::Value(200))
        );

        // Test comparison operations
        assert_eq!(
            parse_single_instruction("[0] = [1] < [2]"),
            Instruction::LessThan(Arg::Mem(1), Arg::Mem(2), Arg::Mem(0))
        );

        assert_eq!(
            parse_single_instruction("[0] = [1] == [2]"),
            Instruction::Equals(Arg::Mem(1), Arg::Mem(2), Arg::Mem(0))
        );

        assert_eq!(
            parse_single_instruction("[R-1] = [R-3] == [R-2]"),
            Instruction::Equals(
                Arg::RelativeMem(-3),
                Arg::RelativeMem(-2),
                Arg::RelativeMem(-1)
            )
        );

        // Test R adjustment
        assert_eq!(
            parse_single_instruction("R += 10"),
            Instruction::AdjustRelativeBase(Arg::Value(10))
        );

        assert_eq!(
            parse_single_instruction("R -= 5"),
            Instruction::AdjustRelativeBase(Arg::Value(-5))
        );

        // Test relative memory addressing
        assert_eq!(
            parse_single_instruction("[0] = [R+5] + [R-3]"),
            Instruction::Add(Arg::RelativeMem(5), Arg::RelativeMem(-3), Arg::Mem(0))
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
            Instruction::Input(Arg::Mem(0)),
            Instruction::Input(Arg::Mem(1)),
            Instruction::Add(Arg::Mem(0), Arg::Mem(1), Arg::Mem(2)),
            Instruction::Output(Arg::Mem(2)),
            Instruction::Halt,
        ];

        assert_eq!(parse_test_program(program), expected);
    }

    #[test]
    fn test_program_with_labels() {
        let program = "
            INPUT [0]       ; Get a number
            [1] = 1 + 0     ; Initialize counter
            loop:           ; Loop start
                [2] = [1] * [0]  ; Multiply
                output [2]  ; Output the result
                [1] = [1] + 1    ; Increment counter
                [3] = [1] < 5    ; Check if counter < 5
                if [3] goto @loop  ; Loop if true
            halt
        ";

        let instructions = parse_test_program(program);

        // The offsets will be calculated by the parser
        // We'll check a few key instructions:
        assert_eq!(instructions[0], Instruction::Input(Arg::Mem(0)));

        // Check the multiplication
        assert_eq!(
            instructions[2],
            Instruction::Mul(Arg::Mem(1), Arg::Mem(0), Arg::Mem(2))
        );

        // Check the loop jump - it should jump to offset 6
        assert_eq!(
            instructions[6],
            Instruction::JumpIf(Arg::Mem(3), true, Arg::Value(6))
        );

        // Check the halt instruction
        assert_eq!(instructions[7], Instruction::Halt);
    }

    #[test]
    fn test_complex_program() {
        let program = "
            ; Initialize variables
            [0] = 0 + 0    ; sum = 0
            [1] = 1 + 0    ; i = 1
            [10] = 10 + 0  ; limit = 10

            ; Main loop to calculate sum of 1 to 10
            loop:
                ; Check if i <= limit
                [2] = [1] < [10]     ; i < limit?
                [3] = [1] == [10]    ; i == limit?
                [4] = [2] + [3]      ; result of i <= limit

                ; If i > limit, exit loop
                if ![4] goto @done

                ; sum += i
                [0] = [0] + [1]

                ; i++
                [1] = [1] + 1

                ; Continue loop
                goto @loop

            done:
                ; Output final sum
                output [0]
                halt
        ";

        let instructions = parse_test_program(program);

        // Verify the program length
        assert_eq!(instructions.len(), 12);

        // Check key instructions

        // Initialize sum
        assert_eq!(
            instructions[0],
            Instruction::Add(Arg::Value(0), Arg::Value(0), Arg::Mem(0))
        );

        // Check loop condition
        assert_eq!(
            instructions[3],
            Instruction::LessThan(Arg::Mem(1), Arg::Mem(10), Arg::Mem(2))
        );

        // Check conditional jump
        assert_eq!(
            instructions[6],
            Instruction::JumpIf(Arg::Mem(4), false, Arg::Value(38))
        );

        // Check final output and halt
        assert_eq!(instructions[10], Instruction::Output(Arg::Mem(0)));
        assert_eq!(instructions[11], Instruction::Halt);
    }

    #[test]
    fn test_nested_labels() {
        let program = "
            ; A program with nested control structures
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

                    ; result += i * j
                    [20] = [1] * [10]
                    [0] = [0] + [20]

                    ; j++
                    [10] = [10] + 1
                    goto @inner_loop

                inner_done:
                    ; i++
                    [1] = [1] + 1
                    goto @outer_loop

            done:
                output [0]
                halt
        ";

        // For this test, we'll just check that it parses without errors
        // and verify the total instruction count
        let instructions = parse_test_program(program);
        assert_eq!(instructions.len(), 16);

        // Verify the final instruction is halt
        assert_eq!(instructions.last().unwrap(), &Instruction::Halt);
    }

    #[test]
    fn test_comments_and_whitespace() {
        let program = "
            ; This program calculates 5 + 7

            ; Initialize values
            [0] = 5 + 0    ; First value

            ; Add second value
            [0] = [0] + 7  ; Add 7

            ; Output the result
            output [0]     ; Should be 12

            ; End program
            halt
        ";

        let expected = vec![
            Instruction::Add(Arg::Value(5), Arg::Value(0), Arg::Mem(0)),
            Instruction::Add(Arg::Mem(0), Arg::Value(7), Arg::Mem(0)),
            Instruction::Output(Arg::Mem(0)),
            Instruction::Halt,
        ];

        assert_eq!(parse_test_program(program), expected);
    }
    #[test]
    fn test_label_position_in_args() {
        let program = "
            ; Test using labels in different positions
            start:
                [0] = 1 + 0  ; 0
                [1] = 2 + 0  ; 4

                ; Label as first argument
                if @loop goto @done   ; 8

                loop:
                ; Label as second argument for arithmatic
                [2] = @loop + 10      ; 11

                ; Label in third position
                [3] = 5 < @done       ; 15

                ; Label as third argument
                [4] = 100 + 200      ; 19
                goto @loop           ; 23

            done:
                output [0]           ; 26
                halt                 ; 27
        ";

        let ops = parse_test_program(program);

        // The if @loop goto @done should use the address of @loop as first arg
        // The [2] = @loop + 10 should use loop's address as first arg
        assert_eq!(
            ops[3],
            Instruction::Add(Arg::Value(11), Arg::Value(10), Arg::Mem(2))
        );

        // The [3] = 5 < @done should use done's address as second arg
        assert_eq!(
            ops[4],
            Instruction::LessThan(Arg::Value(5), Arg::Value(26), Arg::Mem(3))
        );
    }

    #[test]
    fn test_debug_marker() {
        let program = "
            'x [0] = 0 + 0    ; set debug marker 'x on first argument
            [1] = 'y10 + 0    ; set debug marker 'y on second argument
            [2] = 0 + 'z5     ; set debug marker 'z on third argument
            'a ptr = 350      ; set debug marker 'a on pointer
            [3] = 'b *ptr     ; read from pointer
        ";

        let instructions = parse_program(program).unwrap();
        let instructions = instructions.into_iter().map(|(_, inst)| inst).collect_vec();

        // Check first instruction: 'x[0] = 0 + 0
        if let GenericInstruction::Add(arg1, arg2, arg3) = &instructions[0] {
            assert_eq!(arg1.debug_marker, None);
            assert_eq!(arg2.debug_marker, None);
            assert_eq!(arg3.debug_marker, Some('x'));
        } else {
            panic!("Expected Add instruction");
        }

        // Check second instruction: [1] = 'y10 + 0
        if let GenericInstruction::Add(arg1, arg2, arg3) = &instructions[1] {
            assert_eq!(arg1.debug_marker, Some('y'));
            assert_eq!(arg2.debug_marker, None);
            assert_eq!(arg3.debug_marker, None);
        } else {
            panic!("Expected Add instruction");
        }

        // Check third instruction: [2] = 0 + 'z5
        if let GenericInstruction::Add(arg1, arg2, arg3) = &instructions[2] {
            assert_eq!(arg1.debug_marker, None);
            assert_eq!(arg2.debug_marker, Some('z'));
            assert_eq!(arg3.debug_marker, None);
        } else {
            panic!("Expected Add instruction");
        }

        if let GenericInstruction::Assign(arg1, arg2) = &instructions[3] {
            assert_eq!(arg1.debug_marker, Some('a'));
            assert_eq!(arg2.debug_marker, None);
        } else {
            panic!("Expected Assign instruction");
        }
        if let GenericInstruction::Assign(arg1, arg2) = &instructions[4] {
            assert_eq!(arg1.debug_marker, None);
            assert_eq!(arg2.debug_marker, Some('b'));
        } else {
            panic!("Expected Assign instruction");
        }
    }
}
