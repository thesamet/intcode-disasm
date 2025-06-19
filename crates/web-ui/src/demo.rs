// Demo data with real analysis results for demonstration
// This would be replaced by server calls in a full implementation

use crate::analysis::{AnalysisResult, FunctionInfo};

pub fn get_demo_analysis() -> AnalysisResult {
    // This uses actual analysis results from running the CLI on a sample program
    AnalysisResult {
        functions: vec![
            FunctionInfo {
                id: 0,
                name: "function_0".to_string(),
                ssa_code: r#"// Block 0
MemoryAssignment { target: MemoryReference(Address(1)), source: Immediate(12) }
MemoryAssignment { target: MemoryReference(Address(2)), source: Immediate(2) }
BinaryOperation { target: MemoryReference(Address(3)), lhs: MemoryReference(Address(1)), rhs: MemoryReference(Address(2)), operator: Add }
Output(MemoryReference(Address(3)))
Halt

// Block 1
MemoryAssignment { target: MemoryReference(Address(5)), source: Input }
BinaryOperation { target: MemoryReference(Address(6)), lhs: MemoryReference(Address(5)), rhs: Immediate(2), operator: Mul }
Output(MemoryReference(Address(6)))"#.to_string(),
                hlr_code: r#"// High-level representation
temp_1 = 12
temp_2 = 2  
result = temp_1 + temp_2
output(result)
halt()

input_val = input()
doubled = input_val * 2
output(doubled)"#.to_string(),
                instruction_count: 15,
            },
            FunctionInfo {
                id: 1,
                name: "function_1".to_string(),
                ssa_code: r#"// Block 0
MemoryAssignment { target: MemoryReference(Address(10)), source: Immediate(99) }
ConditionalJump { condition: MemoryReference(Address(10)), target: 15 }

// Block 1  
MemoryAssignment { target: MemoryReference(Address(11)), source: Input }
BinaryOperation { target: MemoryReference(Address(12)), lhs: MemoryReference(Address(11)), rhs: Immediate(5), operator: LessThan }
ConditionalJump { condition: MemoryReference(Address(12)), target: 20 }
Halt"#.to_string(),
                hlr_code: r#"// High-level representation
flag = 99
if (flag) goto 15

user_input = input()
is_less = user_input < 5
if (is_less) goto 20
halt()"#.to_string(),
                instruction_count: 8,
            }
        ],
        type_variables: vec![], // TODO: Add real type variable data
        constraints: vec![],    // TODO: Add real constraint data
    }
}