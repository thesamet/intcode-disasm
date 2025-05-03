use std::collections::{HashMap, HashSet};
use log::{debug, info, trace};

use crate::disasm::Error;
use crate::disasm::v2::control_flow::{NextKind, PredecessorKind};
use crate::disasm::v2::instructions::{BinaryOperator, Expression, Instruction, InstructionNode, MemoryReference};
use crate::disasm::v2::native::{NativeInstruction, Opcode, OperandKind};

use super::block::Block;
use super::function::Function;
use super::result::ControlFlowGraphResult;
use crate::disasm::v3::common::Span;
use crate::disasm::v3::id_types::{BlockId, FunctionId};
use crate::disasm::v3::model::{Model, ImageScannerComplete, ControlFlowGraphComplete};

/// Builds the control flow graph from the image scanner results
pub struct ControlFlowGraphBuilder {
    model: Model<ImageScannerComplete>,
    blocks: HashMap<BlockId, Block>,
    functions: HashMap<FunctionId, Function>,
    next_block_id: usize,
}

impl ControlFlowGraphBuilder {
    pub fn new(model: Model<ImageScannerComplete>) -> Self {
        Self {
            model,
            blocks: HashMap::new(),
            functions: HashMap::new(),
            next_block_id: 0,
        }
    }
    
    pub fn run(model: Model<ImageScannerComplete>) -> Result<Model<ControlFlowGraphComplete>, Error> {
        let mut builder = Self::new(model);
        builder.build()
    }
    
    fn build(&mut self) -> Result<Model<ControlFlowGraphComplete>, Error> {
        debug!("Building control flow graph...");
        
        // Process each function from the image scanner result
        let scanner_result = self.model.image_scanner_result.as_ref().unwrap();
        
        for function_id in &scanner_result.recognized_functions {
            let function_details = &scanner_result.function_details[function_id];
            self.process_function(*function_id, function_details)?;
        }
        
        info!("Control flow graph built with {} functions and {} blocks", 
              self.functions.len(), self.blocks.len());
        
        // Create the control flow graph result
        let result = ControlFlowGraphResult {
            functions: self.functions.clone(),
        };
        
        // Return a new model with the updated state
        Ok(Model {
            image_scanner_result: self.model.image_scanner_result.clone(),
            control_flow_graph_result: Some(result),
            data_flow_result: None,
            ssa_result: None,
            function_call_analysis_result: None,
            marker: std::marker::PhantomData,
        })
    }
    
    fn process_function(&mut self, function_id: FunctionId, function_details: &super::super::image_scanner::result::RecognizedFunction) -> Result<(), Error> {
        debug!("Processing function {}", function_id);
        
        // Create blocks for the function
        let mut block_ids = Vec::new();
        let entry_block_id = self.create_block(function_id, function_details.span.start);
        block_ids.push(entry_block_id);
        
        // Find all block boundaries
        let mut boundaries = HashSet::new();
        boundaries.insert(function_details.span.start);
        
        // Add jump targets as block boundaries
        for target in &function_details.jump_targets {
            boundaries.insert(*target);
        }
        
        // Add function call return addresses as block boundaries
        for call in &function_details.function_calls {
            boundaries.insert(call.return_address);
        }
        
        // Create blocks at each boundary
        let mut sorted_boundaries: Vec<_> = boundaries.into_iter().collect();
        sorted_boundaries.sort();
        
        for &boundary in &sorted_boundaries[1..] {
            let block_id = self.create_block(function_id, boundary);
            block_ids.push(block_id);
        }
        
        // Find the return block if it exists
        let return_block = if let Some(return_span) = &function_details.return_span {
            let return_block_id = self.find_block_containing(return_span.start);
            Some(return_block_id)
        } else {
            None
        };
        
        // Create the function
        let mut function = Function {
            function_id,
            entry_block: entry_block_id,
            stack_size: function_details.stack_size,
            return_block,
            blocks: HashMap::new(),
        };
        
        // Process each block to set up control flow
        for block_id in &block_ids {
            let block = self.blocks.get_mut(block_id).unwrap();
            self.process_block(block, function_details)?;
            
            // Add the block to the function
            function.blocks.insert(*block_id, block.clone());
        }
        
        // Add the function to our collection
        self.functions.insert(function_id, function);
        
        Ok(())
    }
    
    fn create_block(&mut self, function_id: FunctionId, start_address: usize) -> BlockId {
        let block_id = BlockId::from(self.next_block_id);
        self.next_block_id += 1;
        
        let block = Block {
            id: block_id,
            containing_function_id: function_id,
            span: Span::new(start_address, start_address), // Will be updated later
            native_instructions: Vec::new(),
            low_instructions: Vec::new(),
            next: NextKind::Fallthrough,
            predecessors: Vec::new(),
        };
        
        self.blocks.insert(block_id, block);
        block_id
    }
    
    fn find_block_containing(&self, address: usize) -> BlockId {
        for (id, block) in &self.blocks {
            if block.span.contains_address(address) {
                return *id;
            }
        }
        panic!("No block found containing address {}", address);
    }
    
    fn process_block(&mut self, block: &mut Block, function_details: &super::super::image_scanner::result::RecognizedFunction) -> Result<(), Error> {
        // Find the native instructions that belong to this block
        let start_address = block.span.start;
        let mut end_address = function_details.span.end;
        
        // Find the next block boundary after this one
        for (_, other_block) in &self.blocks {
            if other_block.span.start > start_address && other_block.span.start < end_address {
                end_address = other_block.span.start;
            }
        }
        
        // Update the block span
        block.span = Span::new(start_address, end_address);
        
        // Find the native instructions for this block
        block.native_instructions = function_details.instructions.iter()
            .filter(|instr| {
                instr.span.start >= start_address && instr.span.start < end_address
            })
            .cloned()
            .collect();
        
        // Convert native instructions to low-level IR
        block.low_instructions = self.convert_to_low_ir(&block.native_instructions)?;
        
        // Determine the next block based on the last instruction
        if let Some(last_instr) = block.native_instructions.last() {
            if last_instr.is_goto() {
                if let Some(target) = last_instr.immediate_goto() {
                    let target_block = self.find_block_containing(target);
                    block.next = NextKind::Goto(target_block);
                } else if let Some(addr) = last_instr.goto_address() {
                    block.next = NextKind::ComputedGoto(Expression::Addressable(addr.clone()));
                }
            } else if last_instr.is_conditional_jump() {
                if let Some(target) = last_instr.conditional_jump_immediate_address() {
                    let target_block = self.find_block_containing(target);
                    let condition = last_instr.conditional_jump_condition().unwrap();
                    let next_block = self.find_block_containing(last_instr.span.end);
                    
                    block.next = NextKind::ConditionalJump {
                        condition: condition.clone(),
                        true_branch: target_block,
                        false_branch: next_block,
                    };
                }
            } else if last_instr.is_halt() {
                block.next = NextKind::Halt;
            } else if !last_instr.is_goto() && !last_instr.is_halt() {
                // Regular fallthrough to the next block
                if last_instr.span.end < function_details.span.end {
                    let next_block = self.find_block_containing(last_instr.span.end);
                    block.next = NextKind::Goto(next_block);
                } else {
                    block.next = NextKind::Halt; // End of function without explicit return
                }
            }
        }
        
        // For function calls, set up the appropriate NextKind
        for call in &function_details.function_calls {
            if call.span.start >= block.span.start && call.span.start < block.span.end {
                let return_block = self.find_block_containing(call.return_address);
                
                // Find the target function if it's an immediate address
                if let OperandKind::Immediate(target_addr) = call.target.kind {
                    let scanner_result = self.model.image_scanner_result.as_ref().unwrap();
                    if let Some(target_function) = scanner_result.address_to_function.get(&(target_addr as usize)) {
                        let target_function_id = *target_function;
                        block.next = NextKind::FunctionCall {
                            function_addr: Expression::Constant(target_addr),
                            return_block,
                            calling_block: block.id,
                        };
                    }
                } else {
                    // Computed function call
                    let target_expr = self.operand_to_expression(&call.target);
                    block.next = NextKind::FunctionCall {
                        function_addr: target_expr,
                        return_block,
                        calling_block: block.id,
                    };
                }
            }
        }
        
        Ok(())
    }
    
    fn convert_to_low_ir(&self, native_instructions: &[NativeInstruction]) -> Result<Vec<InstructionNode<MemoryReference>>, Error> {
        let mut result = Vec::new();
        
        for instr in native_instructions {
            match instr.opcode() {
                Opcode::Add => {
                    if let Some(assignment) = instr.as_assignment() {
                        let target = self.operand_to_memory_reference(&assignment.target);
                        let lhs = self.operand_to_expression(&assignment.source);
                        let rhs = Expression::Constant(assignment.immediate);
                        
                        let instruction = Instruction::Assignment {
                            target,
                            source: Expression::Binary {
                                op: BinaryOperator::Add,
                                lhs: Box::new(lhs),
                                rhs: Box::new(rhs),
                            },
                        };
                        
                        result.push(InstructionNode {
                            instruction,
                            offset: instr.span.start,
                            debug_marker: None,
                        });
                    }
                },
                Opcode::Multiply => {
                    if let Some(assignment) = instr.as_assignment() {
                        let target = self.operand_to_memory_reference(&assignment.target);
                        let lhs = self.operand_to_expression(&assignment.source);
                        let rhs = Expression::Constant(assignment.immediate);
                        
                        let instruction = Instruction::Assignment {
                            target,
                            source: Expression::Binary {
                                op: BinaryOperator::Multiply,
                                lhs: Box::new(lhs),
                                rhs: Box::new(rhs),
                            },
                        };
                        
                        result.push(InstructionNode {
                            instruction,
                            offset: instr.span.start,
                            debug_marker: None,
                        });
                    }
                },
                Opcode::Input => {
                    if let Some(target) = instr.input_target() {
                        let target_ref = self.operand_to_memory_reference(&target);
                        
                        let instruction = Instruction::Input {
                            target: target_ref,
                        };
                        
                        result.push(InstructionNode {
                            instruction,
                            offset: instr.span.start,
                            debug_marker: None,
                        });
                    }
                },
                Opcode::Output => {
                    if let Some(source) = instr.output_source() {
                        let source_expr = self.operand_to_expression(&source);
                        
                        let instruction = Instruction::Output {
                            source: source_expr,
                        };
                        
                        result.push(InstructionNode {
                            instruction,
                            offset: instr.span.start,
                            debug_marker: None,
                        });
                    }
                },
                Opcode::JumpIfTrue | Opcode::JumpIfFalse => {
                    // These are handled at the block level for control flow
                },
                Opcode::LessThan => {
                    if let Some(assignment) = instr.as_assignment() {
                        let target = self.operand_to_memory_reference(&assignment.target);
                        let lhs = self.operand_to_expression(&assignment.source);
                        let rhs = Expression::Constant(assignment.immediate);
                        
                        let instruction = Instruction::Assignment {
                            target,
                            source: Expression::Binary {
                                op: BinaryOperator::LessThan,
                                lhs: Box::new(lhs),
                                rhs: Box::new(rhs),
                            },
                        };
                        
                        result.push(InstructionNode {
                            instruction,
                            offset: instr.span.start,
                            debug_marker: None,
                        });
                    }
                },
                Opcode::Equals => {
                    if let Some(assignment) = instr.as_assignment() {
                        let target = self.operand_to_memory_reference(&assignment.target);
                        let lhs = self.operand_to_expression(&assignment.source);
                        let rhs = Expression::Constant(assignment.immediate);
                        
                        let instruction = Instruction::Assignment {
                            target,
                            source: Expression::Binary {
                                op: BinaryOperator::Equals,
                                lhs: Box::new(lhs),
                                rhs: Box::new(rhs),
                            },
                        };
                        
                        result.push(InstructionNode {
                            instruction,
                            offset: instr.span.start,
                            debug_marker: None,
                        });
                    }
                },
                Opcode::AdjustRelativeBase => {
                    // Skip relative base adjustments as they're handled at the function level
                },
                Opcode::Halt => {
                    let instruction = Instruction::Halt;
                    
                    result.push(InstructionNode {
                        instruction,
                        offset: instr.span.start,
                        debug_marker: None,
                    });
                },
                _ => {
                    // Handle other instructions as needed
                }
            }
        }
        
        Ok(result)
    }
    
    fn operand_to_memory_reference(&self, operand: &crate::disasm::v2::native::Operand) -> MemoryReference {
        match operand.kind {
            OperandKind::Memory(addr) => MemoryReference::Memory(addr),
            OperandKind::RelativeMemory(offset) => MemoryReference::RelativeMemory(offset),
            OperandKind::Immediate(value) => MemoryReference::Immediate(value),
            OperandKind::Pointer(addr) => MemoryReference::Pointer(addr),
            _ => panic!("Cannot convert operand to memory reference: {:?}", operand),
        }
    }
    
    fn operand_to_expression(&self, operand: &crate::disasm::v2::native::Operand) -> Expression<MemoryReference> {
        match operand.kind {
            OperandKind::Memory(addr) => Expression::Addressable(MemoryReference::Memory(addr)),
            OperandKind::RelativeMemory(offset) => Expression::Addressable(MemoryReference::RelativeMemory(offset)),
            OperandKind::Immediate(value) => Expression::Constant(value),
            OperandKind::Pointer(addr) => Expression::Addressable(MemoryReference::Pointer(addr)),
            _ => panic!("Cannot convert operand to expression: {:?}", operand),
        }
    }
}
