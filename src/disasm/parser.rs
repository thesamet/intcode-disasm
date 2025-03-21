use nom::{
    branch::alt,
    bytes::complete::{is_not, tag, take_while1},
    character::complete::{char, digit1, multispace0, space0, space1},
    combinator::{eof, map, map_res, opt, recognize, value},
    multi::{many1, separated_list0},
    sequence::{delimited, pair, preceded, terminated},
    IResult, Parser,
};
use std::collections::HashMap;

// Define our data structures
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Argument {
    Memory(i128),      // Mode 0: [528]
    Immediate(i128),   // Mode 1: 1244
    RelativeMem(i128), // Mode 2: [R+17] or [R-17]
    Label(String),     // For jump instructions
}

impl Argument {
    fn mode(&self) -> i128 {
        match self {
            Argument::Memory(_) => 0,
            Argument::Immediate(_) => 1,
            Argument::RelativeMem(_) => 2,
            Argument::Label(_) => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Instruction {
    Add(Argument, Argument, Argument),      // ADD a, b, c
    Mul(Argument, Argument, Argument),      // MUL a, b, c
    Input(Argument),                        // INPUT a
    Output(Argument),                       // output a
    IfGoto(Argument, Argument),             // if a goto b
    IfNotGoto(Argument, Argument),          // if !a goto b
    LessThan(Argument, Argument, Argument), // c = a < b
    Equals(Argument, Argument, Argument),   // c = a == b
    AdjustR(Argument),                      // R += a
    Halt,                                   // halt
}

impl Instruction {
    pub fn size(&self) -> usize {
        match self {
            Instruction::Add(_, _, _)
            | Instruction::Mul(_, _, _)
            | Instruction::LessThan(_, _, _)
            | Instruction::Equals(_, _, _) => 4,

            Instruction::IfGoto(_, _) | Instruction::IfNotGoto(_, _) => 3,

            Instruction::Input(_) | Instruction::Output(_) | Instruction::AdjustR(_) => 2,

            Instruction::Halt => 1,
        }
    }

    fn arg(&self, index: usize) -> Option<&Argument> {
        match self {
            Instruction::Add(a, b, c)
            | Instruction::Mul(a, b, c)
            | Instruction::LessThan(a, b, c)
            | Instruction::Equals(a, b, c) => match index {
                0 => Some(a),
                1 => Some(b),
                2 => Some(c),
                _ => None,
            },
            Instruction::IfGoto(a, b) | Instruction::IfNotGoto(a, b) => match index {
                0 => Some(a),
                1 => Some(b),
                _ => None,
            },
            Instruction::Input(a) | Instruction::Output(a) | Instruction::AdjustR(a) => match index
            {
                0 => Some(a),
                _ => None,
            },
            Instruction::Halt => None,
        }
    }

    pub fn serialize(&self, out: &mut Vec<i128>) {
        let opcode = match self {
            Instruction::Add(_, _, _) => 1,
            Instruction::Mul(_, _, _) => 2,
            Instruction::Input(_) => 3,
            Instruction::Output(_) => 4,
            Instruction::IfGoto(_, _) => 5,
            Instruction::IfNotGoto(_, _) => 6,
            Instruction::LessThan(_, _, _) => 7,
            Instruction::Equals(_, _, _) => 8,
            Instruction::AdjustR(_) => 9,
            Instruction::Halt => 99,
        } as i128;
        let mode = (0..=2)
            .map(|i| self.arg(i).map(|a| a.mode()).unwrap_or_default() * 10i128.pow((i as u32) + 2))
            .sum::<i128>();
        out.push(opcode + mode);
        for i in 0..3 {
            if let Some(arg) = self.arg(i) {
                let arg = match arg {
                    Argument::Memory(x) => x,
                    Argument::Immediate(x) => x,
                    Argument::RelativeMem(x) => x,
                    Argument::Label(_) => unreachable!(),
                };
                out.push(*arg);
            }
        }
    }
}
// Parse a signed i128
fn parse_i128(input: &str) -> IResult<&str, i128> {
    map_res(recognize(pair(opt(char('-')), digit1)), |s: &str| {
        s.parse::<i128>()
    })
    .parse(input)
}

// Parse arguments
fn parse_memory(input: &str) -> IResult<&str, Argument> {
    alt((
        map(
            delimited(char('['), parse_i128, char(']')),
            Argument::Memory,
        ),
        value(
            Argument::Memory(0),
            delimited(tag("[["), parse_i128, tag("]]")),
        ),
    ))
    .parse(input)
}

fn parse_immediate(input: &str) -> IResult<&str, Argument> {
    map(parse_i128, Argument::Immediate).parse(input)
}

fn parse_relative_mem(input: &str) -> IResult<&str, Argument> {
    alt((
        map(
            delimited(tag("[R+"), parse_i128, char(']')),
            Argument::RelativeMem,
        ),
        map(delimited(tag("[R-"), parse_i128, char(']')), |val| {
            Argument::RelativeMem(-val)
        }),
        value(Argument::RelativeMem(0), tag("[R]")),
    ))
    .parse(input)
}

fn parse_label_ref(input: &str) -> IResult<&str, Argument> {
    map(
        preceded(
            char('@'),
            take_while1(|c: char| c.is_alphanumeric() || c == '_'),
        ),
        |s: &str| Argument::Label(s.to_string()),
    )
    .parse(input)
}

fn parse_argument(input: &str) -> IResult<&str, Argument> {
    alt((
        parse_memory,
        parse_relative_mem,
        parse_label_ref,
        parse_immediate,
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
        |(c, _, _, _, a)| Instruction::Add(a, Argument::Immediate(0), c),
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
        |(_, _, a, _, _, _, b)| Instruction::IfGoto(a, b),
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
        |(_, _, _, a, _, _, _, b)| Instruction::IfNotGoto(a, b),
    )
    .parse(input)
}

fn parse_goto(input: &str) -> IResult<&str, Instruction> {
    map(preceded(pair(tag("goto"), space1), parse_argument), |a| {
        Instruction::IfGoto(Argument::Immediate(1), a)
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
            |(_, _, _, _, a)| Instruction::AdjustR(a),
        ),
        map(
            (tag("R"), space0, tag("-="), space0, parse_argument),
            |(_, _, _, _, a)| {
                // Need to negate the argument for subtract
                match a {
                    Argument::Immediate(val) => Instruction::AdjustR(Argument::Immediate(-val)),
                    Argument::Memory(addr) => Instruction::AdjustR(Argument::Memory(addr)),
                    Argument::RelativeMem(offset) => {
                        Instruction::AdjustR(Argument::RelativeMem(-offset))
                    }
                    Argument::Label(label) => Instruction::AdjustR(Argument::Label(label)),
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
    map(
        terminated(
            take_while1(|c: char| c.is_alphanumeric() || c == '_'),
            char(':'),
        ),
        String::from,
    )
    .parse(input)
}

fn comment(input: &str) -> IResult<&str, ()> {
    value(
        (), // Output is thrown away.
        pair(tag("//"), is_not("\n\r")),
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
) -> Result<Vec<(usize, Instruction)>, nom::Err<nom::error::Error<&str>>> {
    let (input, lines) = many1(parse_line).parse(input)?;
    let (_, _) = eof.parse(input)?;

    // First pass: collect labels and their offsets
    let mut label_offsets = HashMap::new();
    let mut current_offset = 0;
    let mut instructions = Vec::new();

    for (label, instruction) in &lines {
        if let Some(label) = label {
            label_offsets.insert(label.clone(), current_offset);
        }

        instructions.push((current_offset, instruction.clone()));
        current_offset += instruction.size();
    }

    // Second pass: resolve labels to offsets
    let resolved_instructions = instructions
        .into_iter()
        .map(|(offset, instr)| {
            let resolved_instr = match instr {
                Instruction::IfGoto(cond, Argument::Label(label)) => {
                    if let Some(&target) = label_offsets.get(&label) {
                        Instruction::IfGoto(cond, Argument::Immediate(target as i128))
                    } else {
                        return Err(("Undefined label", offset));
                    }
                }
                Instruction::IfNotGoto(cond, Argument::Label(label)) => {
                    if let Some(&target) = label_offsets.get(&label) {
                        Instruction::IfNotGoto(cond, Argument::Immediate(target as i128))
                    } else {
                        return Err(("Undefined label", offset));
                    }
                }
                _ => instr,
            };
            Ok((offset, resolved_instr))
        })
        .collect::<Result<Vec<_>, (&str, usize)>>()
        .map_err(|_| {
            nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))
        })?;

    Ok(resolved_instructions)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper function to parse a single instruction
    fn parse_single_instruction(input: &str) -> Instruction {
        let (_, (_, instr)) = parse_line(input).unwrap();
        instr
    }

    // Helper to parse a complete program and return just the instructions
    fn parse_test_program(input: &str) -> Vec<Instruction> {
        let program = parse_program(input).unwrap();
        program.into_iter().map(|(_, instr)| instr).collect()
    }

    #[test]
    fn test_single_instructions() {
        // Test halt
        assert_eq!(parse_single_instruction("halt"), Instruction::Halt);

        // Test basic arithmetic with new syntax
        assert_eq!(
            parse_single_instruction("[0] = 1 + 2"),
            Instruction::Add(
                Argument::Immediate(1),
                Argument::Immediate(2),
                Argument::Memory(0)
            )
        );

        assert_eq!(
            parse_single_instruction("[10] = [20] * 5"),
            Instruction::Mul(
                Argument::Memory(20),
                Argument::Immediate(5),
                Argument::Memory(10)
            )
        );

        // Test INPUT/output
        assert_eq!(
            parse_single_instruction("INPUT [0]"),
            Instruction::Input(Argument::Memory(0))
        );

        assert_eq!(
            parse_single_instruction("output 42"),
            Instruction::Output(Argument::Immediate(42))
        );

        // Test the alternative output syntax
        assert_eq!(
            parse_single_instruction("output(100)"),
            Instruction::Output(Argument::Immediate(100))
        );

        // Test conditional jumps
        assert_eq!(
            parse_single_instruction("if [0] goto 100"),
            Instruction::IfGoto(Argument::Memory(0), Argument::Immediate(100))
        );

        assert_eq!(
            parse_single_instruction("if ![5] goto 200"),
            Instruction::IfNotGoto(Argument::Memory(5), Argument::Immediate(200))
        );

        // Test comparison operations
        assert_eq!(
            parse_single_instruction("[0] = [1] < [2]"),
            Instruction::LessThan(
                Argument::Memory(1),
                Argument::Memory(2),
                Argument::Memory(0)
            )
        );

        assert_eq!(
            parse_single_instruction("[0] = [1] == [2]"),
            Instruction::Equals(
                Argument::Memory(1),
                Argument::Memory(2),
                Argument::Memory(0)
            )
        );

        assert_eq!(
            parse_single_instruction("[R-1] = [R-3] == [R-2]"),
            Instruction::Equals(
                Argument::RelativeMem(-3),
                Argument::RelativeMem(-2),
                Argument::RelativeMem(-1)
            )
        );

        // Test R adjustment
        assert_eq!(
            parse_single_instruction("R += 10"),
            Instruction::AdjustR(Argument::Immediate(10))
        );

        assert_eq!(
            parse_single_instruction("R -= 5"),
            Instruction::AdjustR(Argument::Immediate(-5))
        );

        // Test relative memory addressing
        assert_eq!(
            parse_single_instruction("[0] = [R+5] + [R-3]"),
            Instruction::Add(
                Argument::RelativeMem(5),
                Argument::RelativeMem(-3),
                Argument::Memory(0)
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
            Instruction::Input(Argument::Memory(0)),
            Instruction::Input(Argument::Memory(1)),
            Instruction::Add(
                Argument::Memory(0),
                Argument::Memory(1),
                Argument::Memory(2),
            ),
            Instruction::Output(Argument::Memory(2)),
            Instruction::Halt,
        ];

        assert_eq!(parse_test_program(program), expected);
    }

    #[test]
    fn test_program_with_labels() {
        let program = "
            INPUT [0]       // Get a number
            [1] = 1 + 0     // Initialize counter
            loop:           // Loop start
                [2] = [1] * [0]  // Multiply
                output [2]  // Output the result
                [1] = [1] + 1    // Increment counter
                [3] = [1] < 5    // Check if counter < 5
                if [3] goto @loop  // Loop if true
            halt
        ";

        let instructions = parse_test_program(program);

        // The offsets will be calculated by the parser
        // We'll check a few key instructions:
        assert_eq!(instructions[0], Instruction::Input(Argument::Memory(0)));

        // Check the multiplication
        assert_eq!(
            instructions[2],
            Instruction::Mul(
                Argument::Memory(1),
                Argument::Memory(0),
                Argument::Memory(2)
            )
        );

        // Check the loop jump - it should jump to offset 6
        assert_eq!(
            instructions[6],
            Instruction::IfGoto(Argument::Memory(3), Argument::Immediate(6))
        );

        // Check the halt instruction
        assert_eq!(instructions[7], Instruction::Halt);
    }

    #[test]
    fn test_complex_program() {
        let program = "
            // Initialize variables
            [0] = 0 + 0    // sum = 0
            [1] = 1 + 0    // i = 1
            [10] = 10 + 0  // limit = 10

            // Main loop to calculate sum of 1 to 10
            loop:
                // Check if i <= limit
                [2] = [1] < [10]     // i < limit?
                [3] = [1] == [10]    // i == limit?
                [4] = [2] + [3]      // result of i <= limit
                
                // If i > limit, exit loop
                if ![4] goto @done
                
                // sum += i
                [0] = [0] + [1]
                
                // i++
                [1] = [1] + 1
                
                // Continue loop
                goto @loop
                
            done:
                // Output final sum
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
            Instruction::Add(
                Argument::Immediate(0),
                Argument::Immediate(0),
                Argument::Memory(0)
            )
        );

        // Check loop condition
        assert_eq!(
            instructions[3],
            Instruction::LessThan(
                Argument::Memory(1),
                Argument::Memory(10),
                Argument::Memory(2)
            )
        );

        // Check conditional jump
        assert_eq!(
            instructions[6],
            Instruction::IfNotGoto(Argument::Memory(4), Argument::Immediate(38))
        );

        // Check final output and halt
        assert_eq!(instructions[10], Instruction::Output(Argument::Memory(0)));
        assert_eq!(instructions[11], Instruction::Halt);
    }

    #[test]
    fn test_nested_labels() {
        let program = "
            // A program with nested control structures
            [0] = 0 + 0    // result = 0
            [1] = 1 + 0    // i = 1
            [2] = 5 + 0    // max = 5
            
            outer_loop:
                [3] = [1] < [2]
                if ![3] goto @done
                
                [10] = 1 + 0    // j = 1
                
                inner_loop:
                    [11] = [10] < [1]
                    if ![11] goto @inner_done
                    
                    // result += i * j
                    [20] = [1] * [10]
                    [0] = [0] + [20]
                    
                    // j++
                    [10] = [10] + 1
                    goto @inner_loop
                    
                inner_done:
                    // i++
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
            // This program calculates 5 + 7
            
            // Initialize values
            [0] = 5 + 0    // First value
            
            // Add second value
            [0] = [0] + 7  // Add 7
            
            // Output the result
            output [0]     // Should be 12
            
            // End program
            halt
        ";

        let expected = vec![
            Instruction::Add(
                Argument::Immediate(5),
                Argument::Immediate(0),
                Argument::Memory(0),
            ),
            Instruction::Add(
                Argument::Memory(0),
                Argument::Immediate(7),
                Argument::Memory(0),
            ),
            Instruction::Output(Argument::Memory(0)),
            Instruction::Halt,
        ];

        assert_eq!(parse_test_program(program), expected);
    }
}
