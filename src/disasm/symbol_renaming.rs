use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{digit1, space1},
    combinator::{map, map_res, opt, recognize},
    sequence::{delimited, preceded},
    IResult,
};
use std::collections::HashMap;

// Helper nom parsers

use nom::Parser;

use super::v3::{
    ssa::{types::VersionableMemoryKind, VersionedMemoryReference},
    FunctionId, PointerId,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolRenaming {
    pub function_names: HashMap<FunctionId, String>,
    pub variable_names: HashMap<VersionedMemoryReference, String>,
}

impl Default for SymbolRenaming {
    fn default() -> Self {
        Self::new()
    }
}

impl SymbolRenaming {
    pub fn new() -> Self {
        Self {
            function_names: HashMap::new(),
            variable_names: HashMap::new(),
        }
    }

    fn add_function_name(&mut self, function_id: FunctionId, name: String) {
        self.function_names.insert(function_id, name);
    }

    fn add_variable_name(&mut self, variable: &VersionedMemoryReference, name: String) {
        self.variable_names.insert(*variable, name);
    }

    pub fn from_lines(lines: &str) -> Result<Self, String> {
        let mut symbol_renaming = SymbolRenaming::new();

        for line in lines.lines() {
            let trimmed_line = line.trim();

            // Skip comments
            if trimmed_line.starts_with('#') || trimmed_line.is_empty() {
                continue;
            }

            match SymbolRenamingLine::parse(trimmed_line) {
                Ok((_, symbol_renaming_line)) => match symbol_renaming_line {
                    SymbolRenamingLine::Function(function_id, name) => {
                        symbol_renaming.add_function_name(function_id, name);
                    }
                    SymbolRenamingLine::Variable(variable, name) => {
                        symbol_renaming.add_variable_name(&variable, name);
                    }
                },
                Err(err) => {
                    return Err(format!("Failed to parse line: {}\nError: {}", line, err));
                }
            }
        }

        Ok(symbol_renaming)
    }
}

fn parse_usize(input: &str) -> IResult<&str, usize> {
    map_res(digit1, |s: &str| s.parse::<usize>()).parse(input)
}

fn parse_i128(input: &str) -> IResult<&str, i128> {
    map_res(recognize((opt(tag("-")), digit1)), |s: &str| {
        s.parse::<i128>()
    })
    .parse(input)
}

fn parse_function_id(input: &str) -> IResult<&str, FunctionId> {
    map(parse_usize, FunctionId::new).parse(input)
}

fn parse_pointer_id(input: &str) -> IResult<&str, PointerId> {
    map(parse_usize, PointerId::new).parse(input)
}

fn parse_memory_kind(input: &str) -> IResult<&str, VersionableMemoryKind> {
    map(parse_usize, VersionableMemoryKind::Memory).parse(input)
}

fn parse_relative_memory_kind(input: &str) -> IResult<&str, VersionableMemoryKind> {
    map(
        preceded(
            tag("R"),
            opt(alt((
                preceded(tag("+"), parse_i128),
                parse_i128, // For negative numbers like R-4, or R (implies R+0)
            ))),
        ),
        |offset_opt| VersionableMemoryKind::RelativeMemory(offset_opt.unwrap_or(0)),
    )
    .parse(input)
}

fn parse_pointer_kind(input: &str) -> IResult<&str, VersionableMemoryKind> {
    map(
        preceded(tag("P"), parse_pointer_id),
        VersionableMemoryKind::Pointer,
    )
    .parse(input)
}

fn parse_versionable_memory_kind(input: &str) -> IResult<&str, VersionableMemoryKind> {
    delimited(
        tag("["),
        alt((
            parse_memory_kind,
            parse_relative_memory_kind,
            parse_pointer_kind,
        )),
        tag("]"),
    )
    .parse(input)
}

struct ParsedVmrParts {
    kind: VersionableMemoryKind,
    version: usize,
}

fn parse_vmr_parts(input: &str) -> IResult<&str, ParsedVmrParts> {
    let (input, kind) = parse_versionable_memory_kind(input)?;
    let (input, _) = tag("_")(input)?;
    let (input, version) = parse_usize(input)?;
    Ok((input, ParsedVmrParts { kind, version }))
}

fn parse_rest_of_line_as_name(input: &str) -> IResult<&str, String> {
    // Parse what looks like an identifier (letters, numbers, underscores)
    let identifier = recognize(nom::multi::many1(alt((
        nom::character::complete::alpha1,
        nom::character::complete::digit1,
        tag("_"),
    ))));

    map(identifier, |s: &str| s.trim().to_string()).parse(input)
}
enum SymbolRenamingLine {
    Function(FunctionId, String),
    Variable(VersionedMemoryReference, String),
}

//
// A symbol renaming file has the following format:
//
//   F 2255 new_name
//   V 2255 [R-4]_2 new_var_name
impl SymbolRenamingLine {
    fn parse(input: &str) -> IResult<&str, Self> {
        alt((
            map(
                (
                    tag("F"),
                    space1,
                    parse_function_id,
                    space1,
                    parse_rest_of_line_as_name,
                ),
                |(_, _, fid, _, name)| SymbolRenamingLine::Function(fid, name),
            ),
            map(
                (
                    tag("V"),
                    space1,
                    parse_function_id,
                    space1,
                    parse_vmr_parts,
                    space1,
                    parse_rest_of_line_as_name,
                ),
                |(_, _, fid, _, vmr_parts, _, name)| {
                    let vmr = VersionedMemoryReference {
                        kind: vmr_parts.kind,
                        function_id: fid,
                        version: vmr_parts.version,
                    };
                    SymbolRenamingLine::Variable(vmr, name)
                },
            ),
        ))
        .parse(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_function_line() {
        let input = "F 1234 function_name";
        let result = SymbolRenamingLine::parse(input);
        assert!(result.is_ok());
        let (_, line) = result.unwrap();
        match line {
            SymbolRenamingLine::Function(fid, name) => {
                assert_eq!(fid, FunctionId::new(1234));
                assert_eq!(name, "function_name");
            }
            _ => panic!("Expected a function line"),
        }
    }

    #[test]
    fn test_parse_variable_line() {
        let input = "V 5678 [R-4]_2 variable_name";
        let result = SymbolRenamingLine::parse(input);
        assert!(result.is_ok());
        let (_, line) = result.unwrap();
        match line {
            SymbolRenamingLine::Variable(vmr, name) => {
                assert_eq!(vmr.function_id, FunctionId::new(5678));
                assert_eq!(vmr.kind, VersionableMemoryKind::RelativeMemory(-4));
                assert_eq!(vmr.version, 2);
                assert_eq!(name, "variable_name");
            }
            _ => panic!("Expected a variable line"),
        }
    }

    #[test]
    fn test_parse_variable_line_with_memory() {
        let input = "V 5678 [100]_2 variable_name";
        let result = SymbolRenamingLine::parse(input);
        assert!(result.is_ok());
        let (_, line) = result.unwrap();
        match line {
            SymbolRenamingLine::Variable(vmr, name) => {
                assert_eq!(vmr.function_id, FunctionId::new(5678));
                assert_eq!(vmr.kind, VersionableMemoryKind::Memory(100));
                assert_eq!(vmr.version, 2);
                assert_eq!(name, "variable_name");
            }
            _ => panic!("Expected a variable line"),
        }
    }

    #[test]
    fn test_parse_variable_line_with_pointer() {
        let input = "V 5678 [P10]_2 variable_name";
        let result = SymbolRenamingLine::parse(input);
        assert!(result.is_ok());
        let (_, line) = result.unwrap();
        match line {
            SymbolRenamingLine::Variable(vmr, name) => {
                assert_eq!(vmr.function_id, FunctionId::new(5678));
                assert_eq!(vmr.kind, VersionableMemoryKind::Pointer(PointerId::new(10)));
                assert_eq!(vmr.version, 2);
                assert_eq!(name, "variable_name");
            }
            _ => panic!("Expected a variable line"),
        }
    }

    #[test]
    fn test_parse_relative_memory_kind_positive_offset() {
        let input = "[R+123]";
        let result = parse_versionable_memory_kind(input);
        assert!(result.is_ok());
        let (_, kind) = result.unwrap();
        assert_eq!(kind, VersionableMemoryKind::RelativeMemory(123));
    }

    #[test]
    fn test_parse_relative_memory_kind_negative_offset() {
        let input = "[R-456]";
        let result = parse_versionable_memory_kind(input);
        assert!(result.is_ok());
        let (_, kind) = result.unwrap();
        assert_eq!(kind, VersionableMemoryKind::RelativeMemory(-456));
    }

    #[test]
    fn test_parse_relative_memory_kind_no_offset() {
        let input = "[R]";
        let result = parse_versionable_memory_kind(input);
        assert!(result.is_ok());
        let (_, kind) = result.unwrap();
        assert_eq!(kind, VersionableMemoryKind::RelativeMemory(0));
    }
    #[test]
    fn test_from_lines_empty() {
        let input = "";
        let result = SymbolRenaming::from_lines(input);
        assert!(result.is_ok());
        let symbol_renaming = result.unwrap();
        assert!(symbol_renaming.function_names.is_empty());
        assert!(symbol_renaming.variable_names.is_empty());
    }

    #[test]
    fn test_from_lines_comments_and_empty_lines() {
        let input = "# This is a comment\n\nF 1234 function_name\n# Another comment\n";
        let result = SymbolRenaming::from_lines(input);
        assert!(result.is_ok());
        let symbol_renaming = result.unwrap();
        assert_eq!(symbol_renaming.function_names.len(), 1);
        assert_eq!(
            symbol_renaming.function_names.get(&FunctionId::new(1234)),
            Some(&"function_name".to_string())
        );
        assert!(symbol_renaming.variable_names.is_empty());
    }

    #[test]
    fn test_from_lines_mixed() {
        let input = "F 1234 function_name\nV 5678 [R-4]_2 variable_name";
        let result = SymbolRenaming::from_lines(input);
        assert!(result.is_ok());
        let symbol_renaming = result.unwrap();
        assert_eq!(symbol_renaming.function_names.len(), 1);
        assert_eq!(
            symbol_renaming.function_names.get(&FunctionId::new(1234)),
            Some(&"function_name".to_string())
        );
        assert_eq!(symbol_renaming.variable_names.len(), 1);
        let vmr = VersionedMemoryReference {
            kind: VersionableMemoryKind::RelativeMemory(-4),
            function_id: FunctionId::new(5678),
            version: 2,
        };
        assert_eq!(
            symbol_renaming.variable_names.get(&vmr),
            Some(&"variable_name".to_string())
        );
    }

    #[test]
    fn test_from_lines_invalid_line() {
        let input = "X 1234 function_name";
        let result = SymbolRenaming::from_lines(input);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Failed to parse line: X 1234 function_name"));
    }
}
