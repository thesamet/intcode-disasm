use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{digit1, space0, space1},
    combinator::{map, map_res, opt, recognize, value},
    sequence::{delimited, preceded},
    IResult,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

// Helper nom parsers

use nom::Parser;

use crate::disasm::v3::type_inference::Type;

use super::v3::{
    define_id_type,
    ssa::{types::VersionableMemoryKind, VersionedMemoryReference},
    FunctionId, PointerId,
};

define_id_type!(CustomTypeId);

static CUSTOM_TYPE_ID_COUNTER: AtomicUsize = AtomicUsize::new(0); // For CustomTypeId

impl CustomTypeId {
    pub fn fresh() -> Self {
        let next = CUSTOM_TYPE_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
        CustomTypeId::new(next)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolRenaming {
    functions: HashMap<FunctionId, FunctionSymbol>,
    variable_names: HashMap<VersionedMemoryReference, (String, Option<Type>)>,
    custom_types: HashMap<CustomTypeId, String>,
    globals: HashMap<usize, (String, Option<Type>)>,
}

impl Default for SymbolRenaming {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionSymbol {
    name: String,
    args: Vec<(String, Option<Type>)>,
}

impl FunctionSymbol {
    pub fn new(name: String, args: Vec<(String, Option<Type>)>) -> Self {
        Self { name, args }
    }

    pub fn name(&self) -> &String {
        &self.name
    }

    pub fn args(&self) -> &Vec<(String, Option<Type>)> {
        &self.args
    }
}

impl SymbolRenaming {
    pub fn new() -> Self {
        Self {
            functions: HashMap::new(),
            variable_names: HashMap::new(),
            custom_types: HashMap::new(),
            globals: HashMap::new(),
        }
    }

    fn add_function(
        &mut self,
        function_id: FunctionId,
        name: String,
        args: Vec<(String, Option<Type>)>,
    ) {
        self.functions
            .insert(function_id, FunctionSymbol::new(name, args));
    }

    fn add_variable_name(
        &mut self,
        variable: &VersionedMemoryReference,
        name: String,
        typ: Option<Type>,
    ) {
        self.variable_names.insert(*variable, (name, typ));
    }

    fn add_global(&mut self, addr: usize, name: String, typ: Option<Type>) {
        self.globals.insert(addr, (name, typ));
    }

    pub fn get_variable_name(&self, variable: &VersionedMemoryReference) -> Option<&String> {
        self.variable_names.get(variable).map(|(name, _)| name)
    }

    pub fn get_variable_type(&self, variable: &VersionedMemoryReference) -> Option<&Type> {
        self.variable_names
            .get(variable)
            .and_then(|(_, typ)| typ.as_ref())
    }

    pub fn get_variables(&self) -> &HashMap<VersionedMemoryReference, (String, Option<Type>)> {
        &self.variable_names
    }

    pub fn get_functions(&self) -> &HashMap<FunctionId, FunctionSymbol> {
        &self.functions
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
                    SymbolRenamingLine::Function(function_id, name, args) => {
                        let resolved_args = args
                            .into_iter()
                            .map(|(arg_name, type_opt)| {
                                let resolved_type = type_opt.and_then(|type_name| {
                                    parse_type(&type_name, &symbol_renaming.custom_types)
                                        .ok()
                                        .map(|(_, parsed_type)| parsed_type)
                                });
                                (arg_name, resolved_type)
                            })
                            .collect();
                        symbol_renaming.add_function(function_id, name, resolved_args);
                    }
                    SymbolRenamingLine::Variable(variable, name, type_opt) => {
                        let ty = type_opt
                            .map(|type_name| {
                                parse_type(&type_name, &symbol_renaming.custom_types)
                                    .map(|(_, parsed_type)| parsed_type)
                                    .map_err(|e| e.to_string())
                            })
                            .transpose()?;
                        symbol_renaming.add_variable_name(&variable, name, ty);
                    }
                    SymbolRenamingLine::CustomType(name) => {
                        let custom_type_id = CustomTypeId::fresh();
                        symbol_renaming.custom_types.insert(custom_type_id, name);
                    }
                    SymbolRenamingLine::Global(addr, name, type_opt) => {
                        let ty = type_opt
                            .map(|type_name| {
                                parse_type(&type_name, &symbol_renaming.custom_types)
                                    .map(|(_, parsed_type)| parsed_type)
                                    .map_err(|e| e.to_string())
                            })
                            .transpose()?;
                        symbol_renaming.add_global(addr, name, ty);
                    }
                },
                Err(err) => {
                    return Err(format!("Failed to parse line: {}\nError: {}", line, err));
                }
            }
        }

        Ok(symbol_renaming)
    }

    pub fn get_function_name(&self, function_id: FunctionId) -> Option<&String> {
        self.functions.get(&function_id).map(|symbol| symbol.name())
    }

    pub fn get_function_args(
        &self,
        function_id: FunctionId,
    ) -> Option<&Vec<(String, Option<Type>)>> {
        self.functions.get(&function_id).map(|v| v.args())
    }

    pub fn get_custom_type(&self, id: CustomTypeId) -> Option<&String> {
        self.custom_types.get(&id)
    }

    pub fn get_custom_types(&self) -> &HashMap<CustomTypeId, String> {
        &self.custom_types
    }

    pub fn get_global(&self, addr: usize) -> Option<&String> {
        self.globals.get(&addr).map(|(name, _)| name)
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

fn parse_identifier(input: &str) -> IResult<&str, String> {
    // Parse what looks like an identifier (letters, numbers, underscores)
    let identifier = recognize(nom::multi::many1(alt((
        nom::character::complete::alpha1,
        nom::character::complete::digit1,
        tag("_"),
    ))));

    map(identifier, |s: &str| s.trim().to_string()).parse(input)
}
#[derive(Debug, Clone, PartialEq, Eq)]
enum SymbolRenamingLine {
    Function(FunctionId, String, Vec<(String, Option<String>)>),
    Variable(VersionedMemoryReference, String, Option<String>),
    CustomType(String),
    Global(usize, String, Option<String>),
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
                    parse_identifier,
                    opt(delimited(
                        tag("("),
                        nom::multi::separated_list0(
                            (tag(","), space0),
                            (parse_identifier, opt(preceded(tag(":"), parse_type_as_str))),
                        ),
                        tag(")"),
                    )),
                    space0,
                ),
                |(_, _, fid, _, name, args_opt, _)| {
                    let args = args_opt.unwrap_or_default().into_iter().collect();
                    SymbolRenamingLine::Function(fid, name, args)
                },
            ),
            map(
                (
                    tag("V"),
                    space1,
                    parse_function_id,
                    space1,
                    parse_vmr_parts,
                    space1,
                    parse_identifier,
                    opt(preceded(space1, parse_type_as_str)),
                    space0,
                ),
                |(_, _, fid, _, vmr_parts, _, name, type_opt, _)| {
                    let vmr = VersionedMemoryReference {
                        kind: vmr_parts.kind,
                        function_id: fid,
                        version: vmr_parts.version,
                    };
                    SymbolRenamingLine::Variable(vmr, name, type_opt)
                },
            ),
            map(
                (tag("T"), space1, parse_identifier, space0),
                |(_, _, name, _)| SymbolRenamingLine::CustomType(name),
            ),
            map(
                (
                    tag("G"),
                    space1,
                    parse_usize,
                    space1,
                    parse_identifier,
                    opt(preceded(space1, parse_type_as_str)),
                    space0,
                ),
                |(_, _, addr, _, name, type_opt, _)| {
                    SymbolRenamingLine::Global(addr, name, type_opt)
                },
            ),
        ))
        .parse(input)
    }
}

fn parse_type_as_str(input: &str) -> IResult<&str, String> {
    // Parse what looks like a type (letters, numbers, underscores, <, >)
    let type_identifier = recognize(nom::multi::many1(alt((
        nom::character::complete::alpha1,
        nom::character::complete::digit1,
        tag("_"),
        tag("<"),
        tag(">"),
    ))));

    map(type_identifier, |s: &str| s.trim().to_string()).parse(input)
}

pub fn parse_type<'a>(
    input: &'a str,
    custom_types: &HashMap<CustomTypeId, String>,
) -> IResult<&'a str, Type> {
    use nom::{
        branch::alt,
        bytes::complete::{tag, take_until},
        combinator::{map, map_res},
        sequence::delimited,
    };

    let parse_basic_type = alt((
        value(Type::Int, tag("Int")),
        value(Type::Bool, tag("Bool")),
        value(Type::Char, tag("Char")),
        value(Type::Any, tag("Any")),
        value(Type::Truthy, tag("Truthy")),
        value(Type::NumericLiteral, tag("NumericLiteral")),
        value(Type::Nothing, tag("Nothing")),
    ));

    let parse_pointer_type = map(
        delimited(tag("Pointer<"), take_until(">"), tag(">")),
        |inner: &str| {
            let (_, pointee) = parse_type(inner, custom_types).unwrap(); // Assume valid inner type
            Type::Pointer(Box::new(pointee))
        },
    );

    let parse_custom_type = map_res(nom::character::complete::alpha1, |name: &str| {
        custom_types
            .iter()
            .find(|(_, v)| v == &name)
            .map(|(id, _)| Type::CustomType(*id))
            .ok_or_else(|| format!("Unknown custom type: {}", name))
    });

    alt((parse_basic_type, parse_pointer_type, parse_custom_type)).parse(input)
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
            SymbolRenamingLine::Function(fid, name, _) => {
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
            SymbolRenamingLine::Variable(vmr, name, type_opt) => {
                assert_eq!(vmr.function_id, FunctionId::new(5678));
                assert_eq!(vmr.kind, VersionableMemoryKind::RelativeMemory(-4));
                assert_eq!(vmr.version, 2);
                assert_eq!(name, "variable_name");
                assert_eq!(type_opt, None);
            }
            _ => panic!("Expected a variable line"),
        }
    }

    #[test]
    fn test_parse_function_line_with_empty_args() {
        let input = "F 1234 function_name()";
        let result = SymbolRenamingLine::parse(input);
        assert!(result.is_ok());
        let (_, line) = result.unwrap();
        match line {
            SymbolRenamingLine::Function(fid, name, args) => {
                assert_eq!(fid, FunctionId::new(1234));
                assert_eq!(name, "function_name");
                assert_eq!(args, Vec::<(String, Option<String>)>::new());
            }
            _ => panic!("Expected a function line"),
        }
    }

    #[test]
    fn test_parse_function_line_with_one_arg() {
        let input = "F 1234 function_name(arg1)";
        let result = SymbolRenamingLine::parse(input);
        assert!(result.is_ok());
        let (_, line) = result.unwrap();
        match line {
            SymbolRenamingLine::Function(fid, name, args) => {
                assert_eq!(fid, FunctionId::new(1234));
                assert_eq!(name, "function_name");
                assert_eq!(args, vec![("arg1".to_string(), None)]);
            }
            _ => panic!("Expected a function line"),
        }
    }

    #[test]
    fn test_parse_function_line_with_multiple_args() {
        let input = "F 1234 function_name(arg1,arg2, arg3)";
        let result = SymbolRenamingLine::parse(input);
        assert!(result.is_ok());
        let (_, line) = result.unwrap();
        match line {
            SymbolRenamingLine::Function(fid, name, args) => {
                assert_eq!(fid, FunctionId::new(1234));
                assert_eq!(name, "function_name");
                assert_eq!(
                    args,
                    vec![
                        ("arg1".to_string(), None),
                        ("arg2".to_string(), None),
                        ("arg3".to_string(), None)
                    ]
                );
            }
            _ => panic!("Expected a function line"),
        }
    }

    #[test]
    fn test_parse_variable_line_with_memory() {
        let input = "V 5678 [100]_2 variable_name";
        let result = SymbolRenamingLine::parse(input);
        assert!(result.is_ok());
        let (_, line) = result.unwrap();
        match line {
            SymbolRenamingLine::Variable(vmr, name, type_opt) => {
                assert_eq!(vmr.function_id, FunctionId::new(5678));
                assert_eq!(vmr.kind, VersionableMemoryKind::Memory(100));
                assert_eq!(vmr.version, 2);
                assert_eq!(name, "variable_name");
                assert_eq!(type_opt, None);
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
            SymbolRenamingLine::Variable(vmr, name, type_opt) => {
                assert_eq!(vmr.function_id, FunctionId::new(5678));
                assert_eq!(vmr.kind, VersionableMemoryKind::Pointer(PointerId::new(10)));
                assert_eq!(vmr.version, 2);
                assert_eq!(name, "variable_name");
                assert_eq!(type_opt, None);
            }
            _ => panic!("Expected a variable line"),
        }
    }
    #[test]
    fn test_parse_variable_line_with_type() {
        let input = "V 5678 [P10]_2 variable_name Int";
        let result = SymbolRenamingLine::parse(input);
        assert!(result.is_ok());
        let (_, line) = result.unwrap();
        match line {
            SymbolRenamingLine::Variable(vmr, name, type_opt) => {
                assert_eq!(vmr.function_id, FunctionId::new(5678));
                assert_eq!(vmr.kind, VersionableMemoryKind::Pointer(PointerId::new(10)));
                assert_eq!(vmr.version, 2);
                assert_eq!(name, "variable_name");
                assert_eq!(type_opt, Some("Int".to_string()));
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
        assert!(symbol_renaming.functions.is_empty());
        assert!(symbol_renaming.variable_names.is_empty());
    }

    #[test]
    fn test_from_lines_comments_and_empty_lines() {
        let input = "# This is a comment\n\nF 1234 function_name\n# Another comment\n";
        let result = SymbolRenaming::from_lines(input);
        assert!(result.is_ok());
        let symbol_renaming = result.unwrap();
        assert_eq!(symbol_renaming.functions.len(), 1);
        assert_eq!(
            symbol_renaming.functions.get(&FunctionId::new(1234)),
            Some(&FunctionSymbol::new("function_name".to_string(), vec![]))
        );
        assert!(symbol_renaming.variable_names.is_empty());
    }

    #[test]
    fn test_from_lines_mixed() {
        let input = "F 1234 function_name\nV 5678 [R-4]_2 variable_name";
        let result = SymbolRenaming::from_lines(input);
        assert!(result.is_ok());
        let symbol_renaming = result.unwrap();
        assert_eq!(symbol_renaming.functions.len(), 1);
        assert_eq!(
            symbol_renaming.functions.get(&FunctionId::new(1234)),
            Some(&FunctionSymbol::new("function_name".to_string(), vec![]))
        );
        assert_eq!(symbol_renaming.variable_names.len(), 1);
        let vmr = VersionedMemoryReference {
            kind: VersionableMemoryKind::RelativeMemory(-4),
            function_id: FunctionId::new(5678),
            version: 2,
        };
        assert_eq!(
            symbol_renaming.variable_names.get(&vmr),
            Some(&("variable_name".to_string(), None))
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
    #[test]
    fn test_parse_custom_type_line() {
        let input = "T MyCustomType";
        let result = SymbolRenamingLine::parse(input);
        assert!(result.is_ok());
        let (_, line) = result.unwrap();
        match line {
            SymbolRenamingLine::CustomType(name) => {
                assert_eq!(name, "MyCustomType");
            }
            _ => panic!("Expected a custom type line"),
        }
    }

    #[test]
    fn test_parse_global_line() {
        let line = "G 576 MyGlobal";
        let result = SymbolRenamingLine::parse(line);
        assert!(result.is_ok(), "Parsing failed: {:?}", result.err());
        let (_, parsed_line) = result.unwrap();
        assert_eq!(
            parsed_line,
            SymbolRenamingLine::Global(576, "MyGlobal".to_string(), None)
        );
    }

    #[test]
    fn test_parse_global_line_with_type() {
        let line = "G 576 MyGlobal Int";
        let result = SymbolRenamingLine::parse(line);
        assert!(result.is_ok(), "Parsing failed: {:?}", result.err());
        let (_, parsed_line) = result.unwrap();
        assert_eq!(
            parsed_line,
            SymbolRenamingLine::Global(576, "MyGlobal".to_string(), Some("Int".to_string()))
        );
    }

    #[test]
    fn test_from_lines_with_custom_type() {
        let input = "T MyCustomType";
        let result = SymbolRenaming::from_lines(input);
        assert!(result.is_ok());
        let symbol_renaming = result.unwrap();
        assert_eq!(symbol_renaming.custom_types.len(), 1);
        assert_eq!(
            symbol_renaming.custom_types.values().next().unwrap(),
            &"MyCustomType".to_string()
        );
    }

    #[test]
    fn test_from_lines_with_global() {
        let input = "G 576 MyGlobal Int";
        let result = SymbolRenaming::from_lines(input);
        assert!(result.is_ok(), "from_lines failed: {:?}", result.err());
        let symbol_renaming = result.unwrap();
        assert_eq!(symbol_renaming.globals.len(), 1);
        assert_eq!(
            symbol_renaming.globals.get(&576),
            Some(&("MyGlobal".to_string(), Some(Type::Int)))
        );
    }

    #[test]
    fn test_from_lines_with_global_no_type() {
        let input = "G 1024 AnotherGlobal";
        let result = SymbolRenaming::from_lines(input);
        assert!(result.is_ok(), "from_lines failed: {:?}", result.err());
        let symbol_renaming = result.unwrap();
        assert_eq!(symbol_renaming.globals.len(), 1);
        assert_eq!(
            symbol_renaming.globals.get(&1024),
            Some(&("AnotherGlobal".to_string(), None))
        );
    }

    #[test]
    fn test_get_function_name() {
        let mut symbol_renaming = SymbolRenaming::new();
        let function_id = FunctionId::new(1234);
        symbol_renaming.add_function(function_id, "function_name".to_string(), vec![]);
        let name = symbol_renaming.get_function_name(function_id);
        assert_eq!(name, Some(&"function_name".to_string()));
    }

    #[test]
    fn test_get_function_args() {
        let mut symbol_renaming = SymbolRenaming::new();
        let function_id = FunctionId::new(1234);
        symbol_renaming.add_function(
            function_id,
            "function_name".to_string(),
            vec![("arg1".to_string(), None), ("arg2".to_string(), None)],
        );
        let args = symbol_renaming.get_function_args(function_id);
        assert_eq!(
            args,
            Some(&vec![
                ("arg1".to_string(), None),
                ("arg2".to_string(), None)
            ])
        );
    }

    #[test]
    fn test_get_variable_name() {
        let mut symbol_renaming = SymbolRenaming::new();
        let variable = VersionedMemoryReference {
            kind: VersionableMemoryKind::Memory(100),
            function_id: FunctionId::new(5678),
            version: 2,
        };
        symbol_renaming.add_variable_name(&variable, "variable_name".to_string(), None);
        let name = symbol_renaming.get_variable_name(&variable);
        assert_eq!(name, Some(&"variable_name".to_string()));
    }
    #[test]
    fn test_from_lines_function_with_args_and_types() {
        let input = "T MyCustomType\nF 1234 function_name(arg1:Int, arg2:MyCustomType)";
        let result = SymbolRenaming::from_lines(input);
        assert!(result.is_ok());
        let symbol_renaming = result.unwrap();
        assert_eq!(symbol_renaming.functions.len(), 1);
        let function_id = FunctionId::new(1234);
        let custom_type_id = *symbol_renaming.custom_types.keys().next().unwrap();
        let expected_function_symbol = FunctionSymbol::new(
            "function_name".to_string(),
            vec![
                ("arg1".to_string(), Some(Type::Int)),
                ("arg2".to_string(), Some(Type::CustomType(custom_type_id))),
            ],
        );

        assert_eq!(
            symbol_renaming.functions.get(&function_id),
            Some(&expected_function_symbol)
        );
    }

    #[test]
    fn test_from_lines_variable_with_type() {
        let input = "T MyCustomType\nV 5678 [R-4]_2 variable_name Int";
        let result = SymbolRenaming::from_lines(input);
        assert!(result.is_ok());
        let symbol_renaming = result.unwrap();
        assert_eq!(symbol_renaming.variable_names.len(), 1);
        let vmr = VersionedMemoryReference {
            kind: VersionableMemoryKind::RelativeMemory(-4),
            function_id: FunctionId::new(5678),
            version: 2,
        };
        assert_eq!(
            symbol_renaming.variable_names.get(&vmr),
            Some(&("variable_name".to_string(), Some(Type::Int)))
        );
    }

    #[test]
    fn test_from_lines_variable_with_custom_type() {
        let input = "T MyCustomType\nV 5678 [R-4]_2 variable_name MyCustomType";
        let result = SymbolRenaming::from_lines(input);
        assert!(result.is_ok());
        let symbol_renaming = result.unwrap();
        assert_eq!(symbol_renaming.variable_names.len(), 1);
        let vmr = VersionedMemoryReference {
            kind: VersionableMemoryKind::RelativeMemory(-4),
            function_id: FunctionId::new(5678),
            version: 2,
        };
        assert_eq!(
            symbol_renaming.variable_names.get(&vmr).unwrap().0,
            "variable_name"
        );

        let expected_type = Type::CustomType(
            *symbol_renaming
                .custom_types
                .keys()
                .next()
                .expect("No custom type found"),
        );
        assert_eq!(
            symbol_renaming.variable_names.get(&vmr).unwrap().1,
            Some(expected_type)
        );
    }
    #[test]
    fn test_from_lines_variable_with_pointer_type() {
        let input = "V 5678 [R-4]_2 variable_name Pointer<Int>";
        let result = SymbolRenaming::from_lines(input);
        assert!(result.is_ok());
        let symbol_renaming = result.unwrap();
        assert_eq!(symbol_renaming.variable_names.len(), 1);
        let vmr = VersionedMemoryReference {
            kind: VersionableMemoryKind::RelativeMemory(-4),
            function_id: FunctionId::new(5678),
            version: 2,
        };
        assert_eq!(
            symbol_renaming.variable_names.get(&vmr).unwrap().0,
            "variable_name"
        );

        let expected_type = Type::Pointer(Box::new(Type::Int));
        assert_eq!(
            symbol_renaming.variable_names.get(&vmr).unwrap().1,
            Some(expected_type)
        );
    }

    #[test]
    fn test_from_lines_variable_with_pointer_to_custom_type() {
        let input = "T MyCustomType\nV 5678 [R-4]_2 variable_name Pointer<MyCustomType>";
        let result = SymbolRenaming::from_lines(input);
        assert!(result.is_ok());
        let symbol_renaming = result.unwrap();
        assert_eq!(symbol_renaming.variable_names.len(), 1);
        let vmr = VersionedMemoryReference {
            kind: VersionableMemoryKind::RelativeMemory(-4),
            function_id: FunctionId::new(5678),
            version: 2,
        };
        assert_eq!(
            symbol_renaming.variable_names.get(&vmr).unwrap().0,
            "variable_name"
        );

        let expected_type = Type::Pointer(Box::new(Type::CustomType(
            *symbol_renaming
                .custom_types
                .keys()
                .next()
                .expect("No custom type found"),
        )));
        assert_eq!(
            symbol_renaming.variable_names.get(&vmr).unwrap().1,
            Some(expected_type)
        );
    }
}
