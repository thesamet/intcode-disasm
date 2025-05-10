use super::{expression::Expression, memory_reference::ReadAddressExtractor};
use crate::disasm::v3::id_types::{BlockId, InstructionId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstructionNode<A> {
    pub id: InstructionId,
    pub kind: Instruction<A>,
}

/// Represents different kinds of low-level instructions.
///
/// Each instruction represents an operation in the intermediate representation.
/// The type parameter `A` represents the type of memory reference (typically `MemoryReference`),
/// which can be addressed (read from or written to) during instruction execution.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Instruction<A> {
    /// Assigns the result of an expression to a target address.
    Assign {
        /// Target location where the result will be stored.
        target: A,
        /// Source expression to evaluate.
        src: Expression<A>,
        /// Debug marker applies to the lhs side.
        target_debug_marker: Option<char>,
    },
    /// Conditional branch instruction.
    If {
        /// Condition to evaluate.
        cond: Expression<A>,
        /// Address to jump to if condition is true.
        then_addr: BlockId,
        /// Address to jump to if condition is false.
        else_addr: BlockId,
    },
    Goto(BlockId),
    /// Calls a function. Does not contain information on arguments and return values.
    Call {
        addr: Expression<A>,
        args: Vec<Expression<A>>,
        return_to: BlockId,
    },
    /// Outputs the result of an expression.
    Output(Expression<A>),
    /// Returns from the current function. Does not contain information on return values.
    Return,
    /// Halts execution.
    Halt,
}

impl<A> Instruction<A> {
    /// Collects the source expressions that this instruction evaluates.
    ///
    /// Different instruction types operate on different kinds of expressions:
    /// - Assign: The source expression to be assigned. Note that evaluating
    ///           the target expression will result in the source expression
    ///           being evaluated. See ReadAddressExtractor for more details.
    /// - If: The condition expression
    /// - Call: The target address expression
    /// - Output: The expression to be output
    /// - Other instructions (Goto, Return, Halt): No expressions
    pub fn collect_source_expressions(&self) -> Vec<&Expression<A>> {
        match self {
            Instruction::Assign { src, .. } => vec![src],
            Instruction::If { cond, .. } => vec![cond],
            Instruction::Goto(_) => vec![],
            Instruction::Call { addr, args, .. } => {
                let mut exprs = vec![addr];
                exprs.extend(args.iter());
                exprs
            }
            Instruction::Output(expr) => vec![expr],
            Instruction::Return | Instruction::Halt => vec![],
        }
    }
    /// Returns the target memory reference that this instruction writes to, if any.
    ///
    /// Only Assign instructions write to memory. For example, in an assignment
    /// like `mem[5] = value`, this would return a reference to memory location 5.
    pub fn get_write_address(&self) -> Option<&A> {
        match self {
            Instruction::Assign { target, .. } => Some(target),
            _ => None,
        }
    }
}

impl<A: ReadAddressExtractor> Instruction<A> {
    /// Collects all memory references that this instruction reads from.
    ///
    /// This method is essential for data flow analysis as it identifies all memory
    /// locations that an instruction depends on. It handles both:
    /// 1. Explicit reads in source expressions (e.g., `[100]` in `[101] = [100] + 5`)
    /// 2. Implicit reads in write targets (e.g., `ptr` in `*ptr = value`)
    ///
    /// The latter case is particularly important for correct liveness analysis and
    /// SSA conversion, as it ensures that pointers used in dereferenced writes are
    /// properly tracked as being read.
    ///
    /// # Returns
    /// A vector of references to all memory locations read by this instruction.
    pub fn collect_read_addresses(&self) -> Vec<&A> {
        // Start with reads from the write target (if any)
        // This is crucial for cases like *ptr = value where ptr is read
        let mut reads = self
            .get_write_address()
            .map_or(vec![], |a| a.extract_read_addresses());
        reads.extend(
            self.collect_source_expressions()
                .iter()
                .flat_map(|e| e.collect_read_addresses()),
        );
        reads
    }
}

impl<A> InstructionNode<A> {
    /// Maps addressable references within the instruction, distinguishing between reads and writes using provided mapping functions.
    ///
    /// This function allows for the transformation of memory references within the instruction, providing separate mapping functions
    /// for read and write contexts.  This is particularly useful when the type of memory reference needs to change based on whether
    /// it's being read from or written to.
    ///
    /// - `map_read` is applied to all memory references within expressions (RHS of Assign, If cond, Call addr, Output expr).
    ///   This function should transform a read-context memory reference (`&A`) into a new expression containing transformed references (`Expression<T>`).
    /// - `map_write` is applied *only* to the target memory reference of an Assign instruction.
    ///   This function should transform a write-context memory reference (`&A`) into a new memory reference of type `T`.
    pub fn flat_map_rw<C, R, W, T>(
        &self,
        context: &mut C,
        mut map_read: R,
        mut map_write: W,
    ) -> InstructionNode<T>
    where
        R: FnMut(&mut C, &A) -> Expression<T>,
        W: FnMut(&mut C, &A) -> T,
        C: std::fmt::Debug, // Keep Debug constraint if needed
    {
        match &self.kind {
            Instruction::Assign {
                target,
                src,
                target_debug_marker,
            } => {
                // must evaluate reads first.
                let src = src.flat_map(&mut |v| map_read(context, v));
                let target = map_write(context, target);
                // Removed debug print
                InstructionNode {
                    id: self.id,
                    kind: Instruction::Assign {
                        target,
                        src,
                        target_debug_marker: *target_debug_marker,
                    },
                }
            }
            Instruction::If {
                cond,
                then_addr,
                else_addr,
            } => InstructionNode {
                id: self.id,
                kind: Instruction::If {
                    cond: cond.flat_map(&mut |v| map_read(context, v)),
                    then_addr: *then_addr,
                    else_addr: *else_addr,
                },
            },
            Instruction::Goto(addr) => InstructionNode {
                id: self.id,
                kind: Instruction::Goto(*addr),
            },
            Instruction::Call {
                addr,
                args,
                return_to,
            } => InstructionNode {
                id: self.id,
                kind: Instruction::Call {
                    addr: addr.flat_map(&mut |v| map_read(context, v)),
                    args: args
                        .iter()
                        .map(|e| e.flat_map(&mut |v| map_read(context, v)))
                        .collect(),
                    return_to: *return_to,
                },
            },
            Instruction::Output(expr) => InstructionNode {
                id: self.id,
                kind: Instruction::Output(expr.flat_map(&mut |v| map_read(context, v))),
            },
            Instruction::Return => InstructionNode {
                id: self.id,
                kind: Instruction::Return,
            },
            Instruction::Halt => InstructionNode {
                id: self.id,
                kind: Instruction::Halt,
            },
        }
    }

    pub fn map_rw<C, R, W, T>(
        &self,
        context: &mut C,
        map_read: &mut R,
        map_write: &mut W,
    ) -> InstructionNode<T>
    where
        R: FnMut(&mut C, &A) -> T,
        W: FnMut(&mut C, &A) -> T,
        C: std::fmt::Debug, // Keep Debug constraint if needed
    {
        self.flat_map_rw(
            context,
            |c, v| Expression::Addressable(map_read(c, v)),
            |c, v| map_write(c, v),
        )
    }

    pub fn map_expr<R>(&self, mut map: R) -> InstructionNode<A>
    where
        A: Clone,
        R: FnMut(&Expression<A>) -> Expression<A>,
    {
        match &self.kind {
            Instruction::Assign {
                target,
                src,
                target_debug_marker,
            } => InstructionNode {
                id: self.id,
                kind: Instruction::Assign {
                    target: target.clone(),
                    src: map(src),
                    target_debug_marker: *target_debug_marker,
                },
            },
            Instruction::If {
                cond,
                then_addr,
                else_addr,
            } => InstructionNode {
                id: self.id,
                kind: Instruction::If {
                    cond: map(cond),
                    then_addr: *then_addr,
                    else_addr: *else_addr,
                },
            },
            Instruction::Goto(addr) => InstructionNode {
                id: self.id,
                kind: Instruction::Goto(*addr),
            },
            Instruction::Call {
                addr,
                args,
                return_to,
            } => InstructionNode {
                id: self.id,
                kind: Instruction::Call {
                    addr: map(addr),
                    args: args.iter().map(|e| map(e)).collect(),
                    return_to: *return_to,
                },
            },
            Instruction::Output(expr) => InstructionNode {
                id: self.id,
                kind: Instruction::Output(map(expr)),
            },
            Instruction::Return => InstructionNode {
                id: self.id,
                kind: Instruction::Return,
            },
            Instruction::Halt => InstructionNode {
                id: self.id,
                kind: Instruction::Halt,
            },
        }
    }
}
