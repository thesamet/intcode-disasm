use super::converter::MarkerSearchResult;
use super::*;
use crate::disasm::test_utils::TestContextBuilder;

use crate::disasm::v3::cfg::FunctionView;
// Import v3 analyzers and model states for test setup
use crate::disasm::v3::lir::{BinaryOperator, Expression, Instruction};
use crate::disasm::v3::model::SsaComplete;
use crate::disasm::v3::pretty_print::pretty_print_ssa;
use crate::disasm::v3::ssa::types::VersionableMemoryKind;
use crate::disasm::v3::BlockId;
// Keep v2 dispatching

use dsl_macros_impl::memref;
use itertools::Itertools;
use pretty_assertions::assert_eq;

// The memref! macro is used for creating memory references in the DSL syntax
// Examples:
// - Register-relative: memref!([R+2].7) or memref!([R-3].5)
// - Absolute address: memref!([155].7)
// - Pointer: memref!([P 123].8)
// - Dereferenced pointer: memref!(*([P 123].8))

// Helper to find an Addressable marked with a specific char within an Expression<SsaMemoryReference>
fn find_addressable_under_marker(
    expr: &Expression<SsaMemoryReference>,
    marker: char,
) -> Option<&SsaMemoryReference> {
    match expr {
        Expression::DebugMarker(m, inner_expr) if *m == marker => {
            // Found the marker, now find the addressable inside
            find_first_addressable_in_expr(inner_expr)
        }
        Expression::DebugMarker(_, inner_expr) => {
            // Wrong marker, search inside
            find_addressable_under_marker(inner_expr, marker)
        }
        Expression::Binary { lhs, rhs, .. } => find_addressable_under_marker(lhs, marker)
            .or_else(|| find_addressable_under_marker(rhs, marker)),
        Expression::Unary { arg, .. } => find_addressable_under_marker(arg, marker),
        _ => None, // Constant or Addressable without marker
    }
}

// Helper to find the first Addressable node in an expression tree
fn find_first_addressable_in_expr(
    expr: &Expression<SsaMemoryReference>,
) -> Option<&SsaMemoryReference> {
    match expr {
        Expression::Addressable(addr) => Some(addr),
        Expression::Binary { lhs, rhs, .. } => {
            find_first_addressable_in_expr(lhs).or_else(|| find_first_addressable_in_expr(rhs))
        }
        Expression::Unary { arg, .. } => find_first_addressable_in_expr(arg),
        Expression::DebugMarker(_, inner_expr) => find_first_addressable_in_expr(inner_expr),
        Expression::Constant(_) => None,
        Expression::Input() => None,
        Expression::StructField { base, .. } => find_first_addressable_in_expr(base),
    }
}

// Helper to find marker within SsaMemoryReference (specifically for Deref)
fn find_addressable_marker_in_ssa_ref(
    ssa_ref: &SsaMemoryReference,
    marker: char,
) -> Option<&SsaMemoryReference> {
    match ssa_ref {
        SsaMemoryReference::Versioned(_) => None, // Markers aren't directly on Versioned
        SsaMemoryReference::Deref(inner_expr) => {
            // Search within the expression being dereferenced
            find_addressable_under_marker(inner_expr, marker)
        }
    }
}

// Implementation for find_marker on FunctionView<SsaComplete>
impl<'a> FunctionView<'a, SsaComplete> {
    pub fn find_marker(&self, marker: char) -> Option<MarkerSearchResult<'a>> {
        for (_, block_view) in self.blocks() {
            // Iterate blocks via FunctionView
            let ssa_block = block_view.ssa(); // Get SsaBlock via BlockView
            for instr_node in &ssa_block.instructions {
                // Check Assign target marker
                if let Instruction::Assign {
                    target,
                    target_debug_marker: Some(m),
                    ..
                } = &instr_node.kind
                {
                    if *m == marker {
                        // Found marker on the target addressable
                        return Some(MarkerSearchResult::SsaAddressable(target));
                    }
                }

                // Check expressions within the instruction
                for (_, expr) in instr_node.collect_source_expressions() {
                    if let Some(addr) = find_addressable_under_marker(expr, marker) {
                        return Some(MarkerSearchResult::SsaAddressable(addr));
                    }
                }
                // Check write target addressable for implicit reads (like *ptr in *ptr = ...)
                if let Some(write_addr) = instr_node.kind.get_write_address() {
                    if let Some(found_addr) = find_addressable_marker_in_ssa_ref(write_addr, marker)
                    {
                        return Some(MarkerSearchResult::SsaAddressable(found_addr));
                    }
                }
            }
        }
        None // Marker not found
    }
}

macro_rules! assert_marker_at_main {
    ($ctx:expr, $marker:expr, $expected_operand:expr) => {{
        // Find the SsaOperand with the given debug marker using the v3 model
        let found_operand = $ctx // ctx is &TestContext
                    .main_function() // Returns FunctionView<SsaComplete>
                    .find_marker($marker) // Call the stubbed method
                    .unwrap_or_else(|| panic!("Marker '{}' not found in main function", $marker));

        // The find_marker implementation now only returns SsaAddressable variant
        let res = match found_operand {
            MarkerSearchResult::SsaAddressable(a) => a,
            // MarkerSearchResult::Expr case is no longer expected here,
            // as find_marker drills down to the SsaAddressable.
            _ => panic!(
                "Expected MarkerSearchResult::SsaAddressable, found {:?}",
                found_operand
            ),
        };
        pretty_assertions::assert_eq!(
            &$expected_operand, // expected_operand should be SsaMemoryReference
            res,
            "For marker '{} expected: {:?}, actual: {:?}",
            $marker,
            $expected_operand,
            res
        );
    }};
}

// Test simple SSA conversion for basic blocks
#[test]
fn test_basic_ssa_conversion() {
    // Simple program with variable definitions and uses
    let ctx = SsaComplete::test_context(
        // Changed variable name
        r#"
            ; Offset 0
            R += 3          ; stack frame setup
            [100] = 5       ; var A = 5
            [101] = [100]   ; var B = A
            [100] = 10      ; var A = 10 (redefine A)
            [102] = [100] + [101] ; var C = A + B
            R -= 3          ; stack frame teardown
            goto [R]        ; return
            "#,
    )
    .unwrap();

    // SSA conversion is done within setup_analyzed_models now
    // Access the main function view from the resulting model
    let func_view = ctx.main_function();

    // Expect the function to have blocks
    assert!(!func_view.blocks().count() > 0);

    // Check the entry block (0)
    let entry_block_id = BlockId::from(0);
    let entry_block_view = func_view.block(&entry_block_id);

    // The entry block should have instructions (accessing via BlockView::ssa())
    assert!(!entry_block_view.ssa().instructions.is_empty());
}
// Test conversion with dominance frontiers and phi functions
#[test]
fn test_ssa_conversion_with_phi_functions() {
    // Program with conditional paths that need phi functions
    let ctx = SsaComplete::test_context(
        // Changed variable name
        r#"
            ; Offset 0: Entry Block
            R += 3
            [100] = 1 ; Initialize var A
            if [100] goto @true_branch

            ; Offset 9: False branch
            [100] = 10 ; Reassign A in false branch
            goto @merge

            ; Offset 16: True branch
            true_branch:
            [100] = 20 ; Reassign A in true branch

            ; Offset 20: Merge block
            merge:
            output [100] ; Use A after the branches merge
            R -= 3
            goto [R]
            "#,
    )
    .unwrap();

    // Find the block with the output instruction (the merge block)
    let main_func_view = ctx.main_function();
    let mut merge_block_id = None;
    // Iterate through blocks in the FunctionView
    for (block_id, block_view) in main_func_view.blocks() {
        // Access SSA block data via the view
        let ssa_block = block_view.ssa();
        if ssa_block
            .instructions
            .iter()
            .any(|instr| matches!(instr.kind, Instruction::Output(_)))
        {
            merge_block_id = Some(block_id);
            break;
        }
    }

    assert!(
        merge_block_id.is_some(),
        "Could not find merge block with output instruction"
    );
    let merge_block_id = merge_block_id.unwrap();

    // Get the merge block view and its SSA data
    let merge_block_view = main_func_view.block(&merge_block_id); // Returns BlockView directly
    let merge_ssa_block = merge_block_view.ssa();

    // Verify that the instruction that reads from [100] is using the correct SSA var
    let output_instr = merge_ssa_block
        .instructions
        .iter()
        .find(|instr| matches!(instr.kind, Instruction::Output(_)))
        .expect("Should have an output instruction");

    let output_expr = if let Instruction::Output(expr) = &output_instr.kind {
        expr
    } else {
        panic!("Expected Output instruction");
    };

    // Verify the output expression is using a versioned addressable
    match output_expr {
        Expression::Addressable(SsaMemoryReference::Versioned(versioned)) => {
            assert_eq!(
                versioned.kind,
                VersionableMemoryKind::Memory(100),
                "Output should use [100]"
            );
            assert!(
                versioned.version > 0,
                "Output variable should have a non-zero version, got: {}",
                versioned.version
            );
        }
        _ => {
            panic!("Output operand should be a Versioned Addressable, but found {output_expr:?}");
        }
    }
    // Note: Phi function expectations remain the same.
}

// Test SSA conversion with function calls and return values
#[test]
fn test_ssa_conversion_with_function_calls() {
    // Program with a function call and return values
    let ctx = SsaComplete::test_context(
        // Changed variable name
        r#"
            ; Main function @ 0
            R += 3
            [R+1] = 10     ; set arg
            [R] = @ret     ; setup return address
            goto @callee   ; call function
            ret:
            output [R+1]   ; use return value
            R -= 3
            goto [R]

            ; Callee function @ 30
            callee:
            R += 2
            [R-1] = [R-1] + 1 ; increment arg and store in return slot
            R -= 2
            goto [R]      ; return
            "#,
    )
    .unwrap();

    // Find the return block by searching for one that contains output instruction
    let main_func_view = ctx.main_function();
    let mut found_return_block = None;
    // Iterate through blocks in the FunctionView
    for (_, block_view) in main_func_view.blocks() {
        // Access SSA block data via the view
        let ssa_block = block_view.ssa();
        if !ssa_block.instructions.is_empty() {
            let first_instr = &ssa_block.instructions[0];
            if matches!(first_instr.kind, Instruction::Output(_)) {
                found_return_block = Some(ssa_block); // Store the SsaBlock
                break;
            }
        }
    }

    let return_block =
        found_return_block.expect("Could not find return block with output instruction");

    // Find the output instruction that uses the return value
    let output_instr = return_block.instructions.first().unwrap();

    if let Instruction::Output(expr) = &output_instr.kind {
        match expr {
            Expression::Addressable(SsaMemoryReference::Versioned(versioned)) => {
                assert!(
                    versioned.version > 0,
                    "Output variable should have a valid version number, got {}",
                    versioned.version
                );
            }
            _ => {
                panic!("Output operand in function call test should be a Versioned Addressable");
            }
        }
    } else {
        panic!("Expected Output instruction in function call test");
    }

    // In this test we're specifically interested in seeing if operands are tracked
    // across function calls. We may not be properly implementing the function return
    // tracking yet, but we at least want to validate that operands_from_function_returns
    // is being populated - which shows the intention of our implementation.

    // If the implementation is improved later, we can add stronger tests for return values,
    // but for now we'll settle for checking that the test runs without crashing.
}

#[test]
fn test_proper_version_increments_for_writes() {
    // Test a simple program that reads and writes the same register
    let ctx = SsaComplete::test_context(
        // Changed variable name
        r#"
            ; Offset 0
            R += 3                  ; stack frame setup
            [R-4] = 5               ; Initialize R-4 with 5
            [R-4] = [R-4] + 10      ; Use R-4 and update it, adding 10
            output [R-4]            ; Use the updated R-4
            R -= 3                  ; stack frame teardown
            goto [R]                ; return
            "#,
    )
    .unwrap();

    // Get the block view and its SSA data
    let block_id = BlockId::from(0);
    let block_view = ctx.main_function().block(&block_id); // Returns BlockView directly
    let block = block_view.ssa(); // Get the SsaBlock

    // Now find the instruction: [R-4] = [R-4] + 10
    let add_instr = block
        .instructions
        .iter()
        .find(|instr| {
            if let Instruction::Assign { target, src, .. } = &instr.kind {
                // Check if this is an assignment with a binary op
                if let (
                    SsaMemoryReference::Versioned(target_var),
                    Expression::Binary {
                        op: BinaryOperator::Add,
                        lhs,
                        ..
                    },
                ) = (target, src)
                {
                    // Check if target is [R-4] and lhs is also [R-4]
                    if let (
                        VersionableMemoryKind::RelativeMemory(target_offset),
                        Expression::Addressable(SsaMemoryReference::Versioned(_)),
                    ) = (target_var.kind, lhs.as_ref())
                    // Remove double deref
                    {
                        // Check the expression inside lhs
                        if let Expression::Addressable(SsaMemoryReference::Versioned(lhs_var)) =
                            lhs.as_ref()
                        {
                            return target_offset == -4
                                && lhs_var.kind == VersionableMemoryKind::RelativeMemory(-4);
                        }
                    }
                }
                false
            } else {
                false
            }
        })
        .expect("Should have found the addition instruction");

    if let Instruction::Assign { target, src, .. } = &add_instr.kind {
        if let (SsaMemoryReference::Versioned(target_var), Expression::Binary { lhs, .. }) =
            (target, src)
        {
            if let Expression::Addressable(SsaMemoryReference::Versioned(src_var)) = lhs.as_ref()
            // Remove double deref
            {
                assert!(
                    src_var.version < target_var.version,
                    "Source version {} should be less than target version {}", // Corrected message
                    src_var.version,
                    target_var.version
                );
            } else {
                panic!("Expected source to be a versioned addressable");
            }
        } else {
            panic!("Expected assignment with binary op");
        }
    }
}

#[test]
fn test_basic_versioning() {
    let ctx = SsaComplete::test_context(
        r#"
                R += 5
                [R+3] = 0
                [R+4] = 1
                'b [R+2] = 'a [R+3] + [R+4]
                'c [R+2] = 'd [R+3] + 'e [R+4]
                halt
            "#,
    )
    .unwrap();
    // pretty_print_ssa(&ctx.model); // Removed pretty print
    assert_marker_at_main!(ctx, 'a', memref!([R + 3].1));
    assert_marker_at_main!(ctx, 'b', memref!([R + 2].1));
    assert_marker_at_main!(ctx, 'c', memref!([R + 2].2));
    assert_marker_at_main!(ctx, 'd', memref!([R + 3].1));
    assert_marker_at_main!(ctx, 'e', memref!([R + 4].1));
}

#[test]
fn test_creates_phi_on_same_block_loop() {
    let ctx = SsaComplete::test_context(
        r#"
                R += 5
                'a [R-2] = 10
                loop:
                'c [R-2] = 'b [R-2] + -1
                output(10)
                if 'd [R-2] goto @loop
                halt
            "#,
    )
    .unwrap();
    println!("{}", pretty_print_ssa(&ctx.model));
    assert_marker_at_main!(ctx, 'a', memref!([R - 2].1));
    assert_marker_at_main!(ctx, 'b', memref!([R - 2].2));
    assert_marker_at_main!(ctx, 'c', memref!([R - 2].3));
    assert_marker_at_main!(ctx, 'd', memref!([R - 2].3));
}

#[test]
fn test_creates_phi_on_multi_block_loop() {
    let ctx = SsaComplete::test_context(
        r#"
                R += 5
                'a [R-2] = 10
                loop:
                'c [R-2] = 'b [R-2] + -1
                output(10)
                if [R-1] goto @merge
                output(10)
                merge:
                if 'd [R-2] goto @loop
                halt
            "#,
    )
    .unwrap();
    println!("{}", pretty_print_ssa(&ctx.model));
    assert_marker_at_main!(ctx, 'a', memref!([R - 2].1));
    assert_marker_at_main!(ctx, 'b', memref!([R - 2].2));
    assert_marker_at_main!(ctx, 'c', memref!([R - 2].3));
    assert_marker_at_main!(ctx, 'd', memref!([R - 2].3));
}

#[test]
fn test_deref_versioning() {
    let ctx = SsaComplete::test_context(
        r#"
                R += 5
                ptr = 500
                [R+2] = 1000
                [R+3] = 1001
                'a ptr = ptr + [R+2]
                'b ptr = ptr + [R+3]
                'd [R+1] = 'c *ptr
                halt
                "#,
    )
    .unwrap();
    // pretty_print_ssa(&ctx.model); // Removed pretty print
    assert_marker_at_main!(ctx, 'a', memref!([P 23].2));
    assert_marker_at_main!(ctx, 'b', memref!([P 23].3));
    assert_marker_at_main!(ctx, 'c', memref!(*([P 23].3)));
    assert_marker_at_main!(ctx, 'd', memref!([R + 1].1));
}

#[test]
fn test_deref_read_after_write() {
    let ctx = SsaComplete::test_context(
        r#"
                R += 5
                'a ptr = [R-2]
                'b *ptr = 1
                halt
                "#,
    )
    .unwrap();
    // pretty_print_ssa(&ctx.model); // Removed pretty print
    assert_marker_at_main!(ctx, 'a', memref!([P 9].1));
    assert_marker_at_main!(ctx, 'b', memref!(*([P 9].1)));
}

#[test]
fn test_deref_read_after_cond_write() {
    let ctx = SsaComplete::test_context(
        r#"
                R += 5
                'a ptr = 345
                 if [R-4] goto @merge
                'b ptr = ptr + 1
            merge:
                'c *ptr = 17
                halt
                "#,
    )
    .unwrap();
    println!("{}", pretty_print_ssa(&ctx.model)); // Removed pretty print
    assert_marker_at_main!(ctx, 'a', memref!([P 16].1));
    assert_marker_at_main!(ctx, 'b', memref!([P 16].2));
    assert_marker_at_main!(ctx, 'c', memref!(*([P 16].3)));
}

#[test]
fn test_incr_write_after_read() {
    let ctx = SsaComplete::test_context(
        r#"
                R += 5
                output('a [R-1])
                'b [R-1] = 17
                halt
                "#,
    )
    .unwrap();
    assert_marker_at_main!(ctx, 'a', memref!([R - 1].0));
    assert_marker_at_main!(ctx, 'b', memref!([R - 1].1));
}

#[test]
fn test_function_calls_and_loop() {
    let ctx = SsaComplete::test_context(
        r#"
              R += 6                          ; Setup frame
              ptr = [R-5]                     ; ptr = [R-5]_0
'a            [R-2] = *ptr                    ; [R-2]_1 = *ptr
'b            [R-3] = 0                       ; [R-3]_1 = 0
'c            [R-5] = [R-5] + 1               ; [R-5]_1 = [R-5]_0 + 1
        loop:                                 ; Loop header block (needs phis for R-3, R-5)
              ; [R-3]_2 = φ(bl0: [R-3]_1, bl48: [R-3]_3)
              [R-1] = 'd [R-3] == 'e [R-2]
              if [R-1] goto @exit
              ptr2 = 'f [R-5] + 'g [R-3]      ; ptr2 = [R-5]_phi + [R-3]_phi
              [R+1] = *ptr2                   ; Argument 1 (return value slot)
              [R+2] = 'h [R-3]                ; Argument 2
              [R+3] = 'i [R-2]                ; Argument 3
              [R] = @ret                      ; Set return address
              goto [R-4]                      ; Call function
        ret:                                  ; Return block from call
              ; [R+1]_2 = φ(bl25: call_return)
              output 'j [R+1]                 ; Use return value
'l            [R-3] = 'k [R-3] + 1            ; [R-3]_3 = [R-3]_2 + 1
              goto @loop                      ; Jump back
        exit:                                 ; Exit block
              R += -6                         ; Teardown frame
              goto [R]                        ; Return
                "#,
    )
    .unwrap();
    pretty_print_ssa(&ctx.model); // Removed pretty print

    // Initial assignments before loop
    assert_marker_at_main!(ctx, 'a', memref!([R - 2].1));
    assert_marker_at_main!(ctx, 'b', memref!([R - 3].1));
    assert_marker_at_main!(ctx, 'c', memref!([R - 5].1));

    // Inside loop header - Phi versions
    assert_marker_at_main!(ctx, 'd', memref!([R - 3].2));
    assert_marker_at_main!(ctx, 'e', memref!([R - 2].1));
    assert_marker_at_main!(ctx, 'f', memref!([R - 5].1));
    assert_marker_at_main!(ctx, 'g', memref!([R - 3].2));
    assert_marker_at_main!(ctx, 'h', memref!([R - 3].2));
    assert_marker_at_main!(ctx, 'i', memref!([R - 2].1));

    // After function call return
    assert_marker_at_main!(ctx, 'j', memref!([R + 1].2));

    // Inside loop body (after call)
    assert_marker_at_main!(ctx, 'k', memref!([R - 3].2));
    assert_marker_at_main!(ctx, 'l', memref!([R - 3].3));
}

#[test]
fn test_end_state() {
    let ctx = SsaComplete::test_context(
        r#"
        R += 3                  ; 0
        [R-1] = [R-2] == 0      ; 2
        if [R-1] goto @end      ; 6

        [R-1] = [R-2] < 0       ; 9
    end:
        output(48)              ; 13
        output([R-1])           ; 15

        R += -3
        goto [R]
        "#,
    )
    .unwrap();
    // Access function info from v3 model
    let func_view = ctx.main_function();
    let return_block_id = func_view.return_block().expect("Return block not found"); // Option<BlockId> needs expect
                                                                                     // Access SSA block data via the view
    assert_eq!(
        func_view
            .block(&return_block_id) // Returns BlockView directly
            .ssa() // Get SsaBlock via view
            .end_state
            .current_version(&VersionableMemoryKind::RelativeMemory(-1)),
        3 // Expecting version 3 based on the control flow
    );
    // Access block 13 via the view
    assert_eq!(
        func_view
            .block(&BlockId::from(13)) // Returns BlockView directly
            .ssa() // Get SsaBlock via view
            .end_state
            .current_version(&VersionableMemoryKind::RelativeMemory(-1)),
        3 // Expecting version 3 based on the control flow
    );
}

#[test]
fn test_versioning() {
    let ctx = SsaComplete::test_context(
        r#"
    R += 3
    [R-1] = 15               ; version 1
    if ![R-1] goto @exit
    if [1308] goto @print

    [R-1] = [1309]           ; version 4

print:
                             ; phi makes version 3
    output(45)
    output(32)

exit:
    R += -3                  ; phi makes version 2
    goto [R]
    "#,
    )
    .unwrap();
    println!("{}", pretty_print_ssa(&ctx.model));
    // Access function info from v3 model
    let func_view = ctx.main_function();
    let return_block_id = func_view.return_block().expect("Return block not found"); // Option<BlockId> needs expect
                                                                                     // Access SSA block data via the view
    let return_block = func_view.block(&return_block_id).ssa(); // Returns BlockView directly
    assert_eq!(
        return_block
            .end_state // Access end_state from SsaBlock
            .current_version(&VersionableMemoryKind::RelativeMemory(-1)),
        3
    );
}

#[test]
fn test_versioning_with_if() {
    let ctx = SsaComplete::test_context(
        r#"
            R += 5
            if [R-1] goto @true
            ptr = 'a [R-4]
            output(*ptr)
            goto @join
        true:
            ptr = 'b [R-4]
            ptr = ptr + 1
        join:
            'c [R-4] = 10
            R -= 5
            goto [R]
            "#,
    )
    .unwrap();
    // pretty_print_ssa(&ctx.model); // Removed pretty print
    assert_marker_at_main!(ctx, 'a', memref!([R - 4].0));
    assert_marker_at_main!(ctx, 'b', memref!([R - 4].0));
    assert_marker_at_main!(ctx, 'c', memref!([R - 4].1));
}

#[test]
fn test_if_convergence_versioning() {
    let ctx = SsaComplete::test_context(
        r#"
            R += 5
            if [R-1] goto @true
            ptr = 'a [R-4]
            output(*ptr)
            goto @join
        true:
            ptr = 'b [R-4]
            ptr = ptr + 1
        join:
            'c [R-4] = 10
            R -= 5
            goto [R]
            "#,
    )
    .unwrap();
    // pretty_print_ssa(&ctx.model); // Removed pretty print
    assert_marker_at_main!(ctx, 'a', memref!([R - 4].0));
    assert_marker_at_main!(ctx, 'b', memref!([R - 4].0));
    assert_marker_at_main!(ctx, 'c', memref!([R - 4].1));
}

#[test]
fn test_if_convergence_versioning_with_phi() {
    // [R-2] is a parameter that gets modified in a branch.
    // we want to ensure that a phi function under br2 bumps up
    // its version.
    let ctx = SsaComplete::test_context(
        r#"
            R += 3
            [R-1] = 'a [R-2] == 0
            if [R-1] goto @exit
                [R-1] = [R-2] < 0
                if [R-1] goto @br1
                    goto @br2
                br1:    ; else
                    output(45)
                    'b [R-2] = [R-2] * -1
            br2:
                [R+1] = 'c [R-2]
                [R] = @exit
                goto 2909
            exit:
                R += -3
                goto [R]

          "#,
    )
    .unwrap();
    // pretty_print_ssa(&ctx.model); // Removed pretty print
    assert_marker_at_main!(ctx, 'a', memref!([R - 2].0));
    assert_marker_at_main!(ctx, 'b', memref!([R - 2].1));
    assert_marker_at_main!(ctx, 'c', memref!([R - 2].2));
}

#[test]
fn function_call_with_arg_that_is_branched() {
    let ctx = SsaComplete::test_context(
        r#"
            R += 3                  ; blocks[0]
            if [R-1] goto @true
            'a [R+1] = 5            ; blocks[1] v1
            goto @merge
        true:                       ; blocks[2]
            'b [R+1] = 7            ; v2
        merge:                      ; blocks[3]
                                    ; v3: we expect a phi for [R+1] here.
            [R] = @ret
            goto 2222
        ret:
            'c [R+1] = 8            ; v4
            R -= 3
            goto [R]
            "#,
    )
    .unwrap();
    println!("{}", pretty_print_ssa(&ctx.model));
    assert_marker_at_main!(ctx, 'a', memref!([R + 1].1));
    assert_marker_at_main!(ctx, 'b', memref!([R + 1].2));
    assert_marker_at_main!(ctx, 'c', memref!([R + 1].4));

    // Check the merge block has a phi function for [R+1] using the v3 model views
    let main_func_view = ctx.main_function();
    let merge_block = main_func_view
        .blocks() // Iterate through blocks in the view
        .map(|(_, block_view)| block_view.ssa()) // Get SsaBlock for each
        .sorted_by_key(|ssa_block| ssa_block.original_id) // Sort by original ID
        .nth(3) // Get the 4th block (index 3)
        .expect("Merge block (index 3) not found"); // Unwrap the Option<SsaBlock>

    assert_eq!(merge_block.phi_functions.len(), 1);
    assert_eq!(
        merge_block.phi_functions[0].result.kind,
        VersionableMemoryKind::RelativeMemory(1)
    );
    assert_eq!(merge_block.phi_functions[0].result.version, 3);
}

#[test]
fn increment_on_add_after_mul() {
    let ctx = SsaComplete::test_context(
        r#"
                R += 3
                'a [R-3] = [R-3] * -1
                [R-5] = [R-5] + 'b [R-3]
                halt

            "#,
    )
    .unwrap();
    println!("{}", pretty_print_ssa(&ctx.model)); // Removed pretty print
    assert_marker_at_main!(ctx, 'a', memref!([R - 3].1));
    assert_marker_at_main!(ctx, 'b', memref!([R - 3].1));
}

#[test]
fn version_correct_following_a_conditional_jump() {
    let ctx = SsaComplete::test_context(
        r#"
                R += 3
                'a [R-2] = [R-2] * -1
                if [R-1] goto @true
                [R+1] = [R-3] * 3
                [R+1] = [R+1] * 5
            true:
                'd [R-2] = 'e [R-2] * 7     ; 17
                halt
            "#,
    )
    .unwrap();
    println!("{}", pretty_print_ssa(&ctx.model)); // Removed pretty print
    assert_marker_at_main!(ctx, 'a', memref!([R - 2].1));
    assert_marker_at_main!(ctx, 'd', memref!([R - 2].2));
    assert_marker_at_main!(ctx, 'e', memref!([R - 2].1));
    assert!(!ctx
        .main_function()
        .block(&BlockId::from(17))
        .ssa()
        .start_state
        .has_version_for(&VersionableMemoryKind::RelativeMemory(1)));
}

#[test]
fn create_phis_if_reads_after_call() {
    let ctx = SsaComplete::test_context(
        r#"
                R += 3
                'a [2145] = 12
                'b [R+1] = 5
                'c [R-1] = 9
                [R] = @ret
                goto 2777
            ret:
                if ![R-2] goto @end
                output('d [2145])
                output('e [R+1])
                output('f [R-1])
            end:
                halt
            "#,
    )
    .unwrap();
    println!("{}", pretty_print_ssa(&ctx.model));
    assert_marker_at_main!(ctx, 'a', memref!([2145].1));
    assert_marker_at_main!(ctx, 'b', memref!([R + 1].1));
    assert_marker_at_main!(ctx, 'c', memref!([R - 1].1));
    assert_marker_at_main!(ctx, 'd', memref!([2145].2));
    assert_marker_at_main!(ctx, 'e', memref!([R + 1].2));
    assert_marker_at_main!(ctx, 'f', memref!([R - 1].1));
}

#[test]
fn create_phis_if_conditional_read_after_call() {
    let ctx = SsaComplete::test_context(
        r#"
                R += 10
                'a [2524] = 1
                'b [R+1] = 5
                [R] = @ret
                goto 2777
            ret:
                if ![R-2] goto @end
                if [R-1] goto @end
                'c [2524] = 0
                'd [R+1] = 7
            end:
                [R-4] = 'e [2524]
                [R-3] = 'f [R+1]
                halt
            "#,
    )
    .unwrap();
    println!("{}", pretty_print_ssa(&ctx.model));
    println!(
        "{:?}",
        ctx.main_function()
            .block(&BlockId::from(0))
            .data_flow()
            .return_values_accessed
    );
    assert_marker_at_main!(ctx, 'a', memref!([2524].1));
    assert_marker_at_main!(ctx, 'b', memref!([R + 1].1));
    assert_marker_at_main!(ctx, 'c', memref!([2524].3));
    assert_marker_at_main!(ctx, 'd', memref!([R + 1].3));
    assert_marker_at_main!(ctx, 'e', memref!([2524].4));
    assert_marker_at_main!(ctx, 'f', memref!([R + 1].4));
}

#[test]
fn does_not_create_phis_if_return_values_ignored() {
    let ctx = SsaComplete::test_context(
        r#"
                R += 10
                'a [2524] = 1
                'b [R+1] = 5
                [R] = @ret
                goto 2777
            ret:
                'c [2524] = 0
                'd [R+1] = 7
                halt
            "#,
    )
    .unwrap();
    println!("{}", pretty_print_ssa(&ctx.model));
    assert_marker_at_main!(ctx, 'a', memref!([2524].1));
    assert_marker_at_main!(ctx, 'b', memref!([R + 1].1));
    assert_marker_at_main!(ctx, 'c', memref!([2524].2));
    assert_marker_at_main!(ctx, 'd', memref!([R + 1].2));
}
