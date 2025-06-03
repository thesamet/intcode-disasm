use crate::disasm::repl::repl;
use crate::disasm::test_utils::TestContextBuilder;

use crate::disasm::v3::model::{Model, TypeInferenceComplete}; // Added more for pretty_print
use crate::disasm::v3::pretty_print::{
    pretty_print_folded_ssa, pretty_print_types, pretty_print_with_types_stdout,
};
use crate::disasm::v3::ssa::types::VersionableMemoryKind;

use crate::disasm::v3::type_inference::type_bounds_map::TypeVarRegistry;
use crate::disasm::v3::type_inference::types::Type;
// V3 Type

// For full implementation, these might be needed:
// use crate::disasm::v3::ssa::{SsaMemoryReference, VersionedMemoryReference};

// Marker types

macro_rules! assert_marker_type {
    ($ctx:expr, $marker:expr, $expected_type:expr) => {
        let model = &$ctx.model; // Get reference to the model from TestContext
        let actual_type = get_marker_type_from_model(model, $marker)
            .unwrap_or_else(|| panic!("No type found for marker '{}'", $marker));

        if std::env::var("REPL").is_ok() {
            if actual_type != $expected_type {
                println!(
                    "Marker {} has incorrect type: expected {:?}, actual {:?}",
                    $marker, $expected_type, actual_type
                );
                repl(&$ctx.model);
            }
        }
        assert_eq!(
            actual_type, $expected_type,
            "Marker {} has incorrect type: expected {:?}, actual {:?}",
            $marker, $expected_type, actual_type
        );
    };
}
macro_rules! panic_or_repl {
        ($ctx:expr, $($arg:tt)*) => {
            if std::env::var("REPL").is_ok() {
                println!($($arg)*);
                repl(&$ctx.model);
                panic!($($arg)*);
            } else {
                panic!($($arg)*);
            }
        };
    }
macro_rules! assert_function_pointer {
    ($ctx:expr, $typ: expr) => {
        // Should be a direct Function type
        let Type::Function { .. } = $typ else {
            panic_or_repl!($ctx, "Not a function pointer, got {:?}", $typ);
        };
    };
}

macro_rules! assert_marker_is_function_pointer {
    ($ctx:expr, $marker:expr) => {
        let actual_type = get_marker_type_from_model(&$ctx.model, $marker).unwrap_or_else(|| {
            panic_or_repl!(
                $ctx,
                "No type found for marker '{}' in assert_marker_is_function_pointer",
                $marker
            )
        });
        let Type::Function { .. } = actual_type else {
            panic_or_repl!(
                $ctx,
                "Marker {} is not a function pointer, got {:?}",
                $marker,
                actual_type
            );
        };
    };
}

// --- Start of Stub Helper Functions ---

fn get_marker_type_from_model(model: &Model<TypeInferenceComplete>, marker: char) -> Option<Type> {
    model.type_inference_result().get_marker_type(marker)
}

fn print_traces_for_marker(_model: &Model<TypeInferenceComplete>, marker: char) {
    // STUB implementation
    println!("STUB: print_traces_for_marker for marker '{marker}'");
}

fn get_type_at_addr_from_model(model: &Model<TypeInferenceComplete>, addr: usize) -> Option<Type> {
    let type_inf_result = model.type_inference_result();

    type_inf_result
        .get_all_inferred_types()
        .iter()
        .filter_map(|(var_kind, type_val)| {
            if let Some(vmr) = var_kind.vmr {
                if let VersionableMemoryKind::Memory(mem_addr) = vmr.kind {
                    if mem_addr == addr {
                        return Some((
                            var_kind,
                            vmr.version,
                            type_inf_result.resolve_type(type_val),
                        ));
                    }
                }
            }
            None
        })
        .max_by_key(|(_, version, _)| *version)
        .map(|(_, _, type_val)| type_val)
        .clone()
}

fn assert_type_on_model(model: &Model<TypeInferenceComplete>, addr: usize, expected_type: Type) {
    let actual_type = get_type_at_addr_from_model(model, addr).unwrap_or_else(|| {
            panic!(
                "No type found for address {addr} during assert_type_on_model. Expected {expected_type:?}."
            )
        });
    assert_eq!(
        actual_type, expected_type,
        "Address {addr} has incorrect type: expected {expected_type:?}, actual {actual_type:?}"
    );
}

// --- End of Stub Helper Functions ---

/*
fn get_marker_type(&self, marker: char) -> Type {
    let ssa_var = self
        .model
        .get_ssa_result()
        .unwrap()
        .find_ssa_operand_by_marker(marker);

    self.model
        .get_type_inference_result()
        .unwrap()
        .get_type_for_ssavar(ssa_var.as_variable().unwrap())
        .unwrap_or_else(|| panic!("No type found for SSA variable marker {}", marker))
        .clone()
}

fn get_type_at_addr(&self, addr: usize) -> Option<&Type> {
    let ti = self.model.get_type_inference_result().unwrap();

    let var = ti
        .inferred_types
        .keys()
        .filter(|var| {
            var.as_ssavar()
                .is_some_and(|v| v.kind.get_memory() == Some(addr))
        })
        .max_by_key(|var| var.as_ssavar().unwrap().version)
        .unwrap_or_else(|| panic!("No type variable found for address {}", addr));

    ti.get_type_for_ssavar(var.as_ssavar().unwrap())
}

fn assert_type(&self, addr: usize, expected: Type) {
    let Some(actual) = self.get_type_at_addr(addr) else {
        panic!("No type found for address {}", addr);
    };
    assert_eq!(
        *actual, expected,
        "Expected type {:?} but got {:?} for memory address {}",
        expected, actual, addr
    );
}

fn print_traces_for_marker(&self, marker: char) {
    let ssa_var = self
        .model
        .get_ssa_result()
        .unwrap()
        .find_ssa_operand_by_marker(marker);
    let kind = VariableKind::SsaVar(*ssa_var.as_variable().unwrap());
    println!(
        "Trace history for {}:\n{}\nType inference completed successfully",
        marker,
        self.model
            .get_type_inference_result()
            .unwrap()
            .format_traces_for_var(kind)
    );
}
*/

/// Test for type conflicts
#[ignore]
#[test]
fn test_type_conflict() {
    let assembly = r#"
            R += 1000
            [R+1] = @ffunc
            [R] = @ret
            goto @foo
        ret:
            halt


        foo:
            R += 2
            [R+1] = 66
            [R] = @foo_ret
            goto [R-1]
        foo_ret:
            ptr = [R-1]
            output('a *ptr)     ; deref a function pointer into a char
            R -= 2
            goto [R]

        ffunc:
            R += 2
            output([R-1])
            R -= 2
            goto [R]
            halt
        "#;

    // Create the TestContext, which runs the full analysis pipeline
    match TypeInferenceComplete::test_context(assembly) {
        Err(e) => {
            assert!(e.to_string().contains("Type conflict for [R-1]_0"));
        }
        Ok(ctx) => {
            println!(
                "Pretty printed model with types (V3):\n{}",
                pretty_print_types(&ctx.model)
            );
            ctx.model.type_inference_result().print_all_type_bounds();
            panic!("Expected test_context to fail.");
        }
    }
}

#[test]
fn test_type_inference() {
    let ctx = TypeInferenceComplete::test_context(
        r#"
        R += 5000
        [503] = 'a [501] + [502]
        [503] = [503] * 9    ; forces [3] to be an int
        [R+1] = 17
        [R+2] = 1
        [R] = @res
        goto @f1
res:
        halt
f1:
        R += 4
        [521] = [R-3]
        if 'b [R-2] goto @f1
        R -= 4
        goto [R]

        "#,
    )
    .unwrap();

    // Use the V3 pretty_print_with_types. It requires the model to implement certain traits.
    // The Model<TypeInferenceComplete> should satisfy these.
    println!(
        "Pretty printed model with types (V3):\n{}",
        pretty_print_types(&ctx.model)
    );
    ctx.model.type_inference_result().print_all_type_bounds();

    assert_type_on_model(&ctx.model, 501, Type::Int);
    assert_marker_type!(ctx, 'a', Type::Int); // Macro now uses ctx.model and stub helper
    print_traces_for_marker(&ctx.model, 'b'); // Use new stub helper
    assert_marker_type!(ctx, 'b', Type::Truthy); // Macro now uses ctx.model and stub helper
}

#[test]
fn test_boolean_comparison() {
    let ctx = TypeInferenceComplete::test_context(
        r#"
            R += 1000
            [1000] = [1001] < [1002]
            halt
        "#,
    )
    .unwrap();
    println!(
        "Pretty printed model with types (V3):\n{}",
        pretty_print_types(&ctx.model)
    );
    ctx.model.type_inference_result().print_all_type_bounds();
    assert_type_on_model(&ctx.model, 1000, Type::Bool);
    assert_type_on_model(&ctx.model, 1001, Type::Int);
    assert_type_on_model(&ctx.model, 1002, Type::Int);
}

#[test]
fn test_output_implies_char() {
    let ctx = TypeInferenceComplete::test_context(
        r#"
            R += 1000
            output [1001]
            halt
        "#,
    )
    .unwrap();
    assert_type_on_model(&ctx.model, 1001, Type::Char);
}

#[test]
fn test_function_addr() {
    let ctx = TypeInferenceComplete::test_context(
        r#"
                R += 1000
                [1001] = [R-2]
                [R] = @ret
                goto [R-2]
                ret:
                halt

            "#,
    )
    .unwrap();
    let typ = get_type_at_addr_from_model(&ctx.model, 1001).unwrap();
    assert_function_pointer!(ctx, typ);
}

#[test]
fn test_function_addr_with_debug() {
    let ctx = TypeInferenceComplete::test_context(
        r#"
                    R += 3
                    'd [R+1] = 'a [R-2]
                    [R+1] = 15
                    'c [R+1] = 'b [R+1] + 5
                    [R] = @ret
                    goto [R-2]
            ret:
                    halt
                "#,
    )
    .unwrap();
    println!(
        "Pretty printed model with types (V3):\n{}",
        pretty_print_types(&ctx.model)
    );
    ctx.model.type_inference_result().print_all_type_bounds();
    print_traces_for_marker(&ctx.model, 'a');
    assert_marker_is_function_pointer!(ctx, 'a');
    // assert_marker_type!(ctx, 'b', Type::Int);
    // assert_marker_type!(ctx, 'c', Type::Int);
    assert_marker_is_function_pointer!(ctx, 'd');
}

#[test]
fn test_link_function_params_to_argument_types() {
    let ctx = TypeInferenceComplete::test_context(
        r#"
                R += 1000
                output('d [R-3])
                'a [R+1] = 65
                [R] = @ret
                goto @print
    ret:
                halt
    print:
                R += 4
                output('b [R-3])
                R -= 4
                goto [R]
            "#,
    )
    .unwrap();
    println!(
        "Pretty printed model with types (V3):\n{}",
        pretty_print_types(&ctx.model)
    );
    assert_marker_type!(ctx, 'd', Type::Char);
    assert_marker_type!(ctx, 'b', Type::Char);
}

#[test]
fn test_link_function_params_to_argument_types_single() {
    let ctx = TypeInferenceComplete::test_context(
        r#"
                R += 1000
                'a [R+1] = 65
                [R] = @ret
                goto @maybe_print
    ret:
                halt
    maybe_print:
                R += 10
                if 'b [R-9] goto @fret
                output 1
    fret:
                R -= 10
                goto [R]
            "#,
    )
    .unwrap();
    println!(
        "Pretty printed model with types (V3):\n{}",
        pretty_print_types(&ctx.model)
    );
    assert_marker_type!(ctx, 'a', Type::Truthy);
    assert_marker_type!(ctx, 'b', Type::Truthy);
}

#[test]
fn test_link_function_params_to_argument_types_multi() {
    let ctx = TypeInferenceComplete::test_context(
        r#"
                R += 1000
                'a [R+1] = 65
                'b [R+2] = 66
                'c [R+3] = @somefunc
                'd [R+4] = 68
                [R] = @ret
                goto @print
    ret:
                halt
    print:
                R += 10
                output([R-9])
                if [R-8] goto @fret
    fret:
                [R+1] = 3
                [R] = @call_ret
                goto [R-7]
    call_ret:
                ptr = [R-6]
                [R-2] = *ptr
                if [R-2] goto @done
    done:
                R -= 10
                goto [R]

    somefunc:
                R += 2
                [R-1] = 17
                R -= 2
                goto [R]
            "#,
    )
    .unwrap();
    println!(
        "Pretty printed model with types (V3):\n{}",
        pretty_print_types(&ctx.model)
    );
    assert_marker_type!(ctx, 'a', Type::Char);
    assert_marker_type!(ctx, 'b', Type::Truthy);
    assert_marker_is_function_pointer!(ctx, 'c');
    assert_marker_type!(ctx, 'd', Type::pointer(Type::Truthy));
}

#[test]
fn use_function_pointer_for_conditional_jump() {
    let ctx = TypeInferenceComplete::test_context(
        r#"
                R += 1000
                'a [R-1] = [5000]
                'b [R+1] = 65
                if ![R-1] goto @ret
                [R] = @ret
                goto [R-1]
    ret:
                halt
            "#,
    )
    .unwrap();
    println!(
        "Pretty printed model with types (V3):\n{}",
        pretty_print_types(&ctx.model)
    );
    assert_marker_is_function_pointer!(ctx, 'a');
}

#[test]
fn test_link_function_return_type_single() {
    // This test also happens to use the same constant (65) for multiple variables
    // testing that each copy can have a different type.
    let ctx = TypeInferenceComplete::test_context(
        r#"
                R += 1000
                'a [R-3] = @add
                'b [R+1] = 65
                'c [R+2] = 65
                'd [R+3] = 65
                [R] = @ret
                goto @add
    ret:
                'f [R+1] = [R+3]
                halt
    add:
                R += 5
                output([R-2])
                'e [R-2] = [R-3] < [R-4]
                R -= 5
                goto [R]
                "#,
    )
    .unwrap();
    println!(
        "Pretty printed model with types (V3):\n{}",
        pretty_print_types(&ctx.model)
    );

    assert_marker_type!(ctx, 'b', Type::Int);
    assert_marker_type!(ctx, 'c', Type::Int);
    assert_marker_type!(ctx, 'd', Type::Char);
    assert_marker_type!(ctx, 'e', Type::Bool);
    assert_marker_type!(ctx, 'f', Type::Bool);
}

#[test]
fn test_reconcile_truthy_with_pointer_across_functions() {
    let ctx = TypeInferenceComplete::test_context(
        r#"
                R += 1000
                'a [320] = 17
                'b [R+1] = 320
                [R] = @ret
                goto @print_char_after_pointer
    ret:
                if ![R+1] goto @end
                'e [R-1] = [R+1]
    end:
                halt
    print_char_after_pointer:
                R += 5
                [R-1] = 2 * 35
                [R-4] = 'f [R-4] + [R-1]  ; forces 'f to be Pointer(char)
                'd ptr = 'e [R-4]
                [R-1] = *ptr
                output('c [R-1])
                R -= 5
                goto [R]
            "#,
    )
    .unwrap();
    println!(
        "Pretty printed model with types (V3):\n{}",
        pretty_print_types(&ctx.model)
    );
    assert_marker_type!(ctx, 'a', Type::Int); // not smart enough yet to see it's char.
    assert_marker_type!(ctx, 'b', Type::pointer(Type::Char));
    assert_marker_type!(ctx, 'e', Type::pointer(Type::Char));
    // [R-4] <: [R+1]
    // [R-4] <: Pointer(Char)
    // [R+1] <: Truthy
}

#[test]
fn test_signatures_for_indirect_calls() {
    let ctx = TypeInferenceComplete::test_context(
        r#"
            R += 1000
            ; Setup call to func_a (takes int, returns char)
            'a [R+1] = @op1
            [R] = @ret1
            goto @makes_indirect_call
        ret1:
            'b [R+1] = @op2
            [R] = @ret2
            goto @makes_indirect_call
        ret2:
            [R-1] = 'm [R+1] * 17
        halt

    makes_indirect_call:
            R += 4
            's [R+1] = 3
            'r [R+2] = 54
            [R] = @fret
            goto 'x [R-3]
        fret:
            [R-3] = [R+1]
            R -= 4
            goto [R]

    op1:
            R += 4
            [R-1] = [R-3] * 7
            output([R-2])
            [R-3] = 35
            R -= 4
            goto [R]

    op2:
            R += 4
            [R-1] = [R-3] * 16
            output([R-2])
            [R-3] = 35
            R -= 4
            goto [R]
            "#,
    )
    .unwrap();
    println!(
        "Pretty printed model with types (V3):\n{}",
        pretty_print_types(&ctx.model)
    );
    /*
    let t_id = ctx
        .model
        .type_inference_result()
        .type_id_for_node(TypeVarNode {
            kind: TypeVarKind::Const(54),
            instruction_id: InstructionId::new(8),
            function_id: FunctionId::new(29),
        });

    ctx.model
        .type_inference_result()
        .query_engine
        .list_variable_changes(TypeVarId::new(20));
        */

    assert_marker_type!(
        ctx,
        'a',
        Type::function_pointer_type(&[Type::Int, Type::Char], &[Type::Int, Type::Int])
    );
    assert_marker_type!(
        ctx,
        'b',
        Type::function_pointer_type(&[Type::Int, Type::Char], &[Type::Int, Type::Int])
    );
    assert_marker_type!(
        ctx,
        'x',
        Type::function_pointer_type(&[Type::Int, Type::Char], &[Type::Int])
    );
    assert_marker_type!(ctx, 's', Type::Int);
    assert_marker_type!(ctx, 'r', Type::Char);
    assert_marker_type!(ctx, 'm', Type::Int);
}

#[test]
fn test_function_pointers_different_args() {
    let ctx = TypeInferenceComplete::test_context(
        r#"
            R += 1000
            'a [R+1] = 'x @op1
            [R] = @ret1
            goto @makes_indirect_call
        ret1:
            'b [R+1] = @op2
            [R] = @ret2
            goto @makes_indirect_call
        ret2:
            [R-1] = 'm [R+1] * 17
        halt

    makes_indirect_call:
            R += 4
            's [R+1] = 3
            'r [R+2] = 54
            [R] = @fret
            goto 'x [R-3]
        fret:
            [R-3] = [R+1]
            R -= 4
            goto [R]

    op1:
            R += 4
            [R-1] = [R-3] * 7
            output([R-2])
            [R-3] = 35
            R -= 4
            goto [R]

    op2:  ; this time op2 only takes one argument
            R += 4
            [R-1] = [R-3] * 16
            ;    output([R-2])  ; intentionally commented out
            [R-3] = 35
            R -= 4
            goto [R]
            "#,
    )
    .unwrap();
    println!(
        "Pretty printed model with types (V3):\n{}",
        pretty_print_types(&ctx.model)
    );
}

#[test]
fn test_pointer_arithmetic_case1() {
    let ctx = TypeInferenceComplete::test_context(
        r#"
            R += 1000

            ; Test case 1: If left operand is a pointer, right operand must be an integer
            [R+100] = 1000
            'a ptr_a = [R+100]
            [R+101] = *ptr_a        ; Define [R+100] as a pointer
            output('b [R+101])            ; Force [R+101] to be a char
            [R+102] = 5             ; Define right operand
            'q [R+103] = ptr_a + 'c [R+102]  ; left is pointer, right must be int

            halt
            "#,
    )
    .unwrap();
    println!(
        "Pretty printed model with types (V3):\n{}",
        pretty_print_folded_ssa(&ctx.model)
    );

    // Test case 1: [R+100] is a pointer, [R+102] must be an integer, result must be a pointer
    assert_marker_type!(ctx, 'a', Type::pointer(Type::Char));
    assert_marker_type!(ctx, 'b', Type::Char);
    assert_marker_type!(ctx, 'c', Type::Int);
    assert_marker_type!(ctx, 'q', Type::pointer(Type::Char));
}

#[test]
fn test_pointer_arithmetic_case2() {
    let ctx = TypeInferenceComplete::test_context(
        r#"
            R += 1000

            ; Test case 2: If right operand is a pointer, left operand must be an integer
            [R+200] = 2000
            'd ptr_b = [R+200]
            [R+201] = *ptr_b        ; Define [R+200] as a pointer
            output('e [R+201])            ; Force [R+201] to be a char
            [R+202] = 10            ; Define left operand
            'r [R+203] = 'f [R+202] + ptr_b  ; right is pointer, left must be int

            halt
            "#,
    )
    .unwrap();
    println!(
        "Pretty printed model with types (V3):\n{}",
        pretty_print_types(&ctx.model)
    );

    // Test case 2: [R+200] is a pointer, [R+202] must be an integer, result must be a pointer
    assert_marker_type!(ctx, 'd', Type::pointer(Type::Char));
    assert_marker_type!(ctx, 'e', Type::Char);
    assert_marker_type!(ctx, 'f', Type::Int);
    assert_marker_type!(ctx, 'r', Type::pointer(Type::Char));
}

#[test]
fn test_pointer_arithmetic_case3() {
    let ctx = TypeInferenceComplete::test_context(
            r#"
            R += 1000

            ; Test case 3: When one operand is a known integer and the result is a pointer,
            ; the other operand must be inferred as a pointer
            [R+300] = 3000          ; Address value, not forced to be pointer yet
            'h [R+301] = 20            ; Will be established as an integer through its use
            'i [R+302] = [R+301] * 2   ; Force [R+301] to be an integer through multiplication
            [R+303] = 'g [R+300] + [R+301]  ; [R+301] is int, so [R+300] should be inferred as pointer
            ptr_sum3 = 's [R+303]
            [R+304] = *ptr_sum3     ; Force result [R+303] to be a pointer via dereferencing
            output('o [R+304])            ; Force [R+304] to be a char

            halt
            "#,
        )
        .unwrap();
    pretty_print_with_types_stdout(&ctx.model);

    // Test case 3: [R+301] is an integer, [R+300] must be a pointer, result is pointer
    assert_marker_type!(ctx, 'g', Type::pointer(Type::Char));
    assert_marker_type!(ctx, 'h', Type::Int);
    assert_marker_type!(ctx, 'i', Type::Int);
    assert_marker_type!(ctx, 's', Type::pointer(Type::Char));
    assert_marker_type!(ctx, 'o', Type::Char);
}

#[test]
fn test_pointer_arithmetic_case4() {
    let ctx = TypeInferenceComplete::test_context(
            r#"
            R += 1000

            ; Test case 4: When one operand is a known integer and the result is a pointer,
            ; the other operand must be inferred as a pointer. Opposite operands to case 3.
            [R+300] = 3000          ; Address value, not forced to be pointer yet
            'h [R+301] = 20            ; Will be established as an integer through its use
            'i [R+302] = [R+301] * 2   ; Force [R+301] to be an integer through multiplication
            [R+303] = [R+301] + 'g [R+300]  ; [R+301] is int, so [R+300] should be inferred as pointer
            ptr_sum3 = 's [R+303]
            [R+304] = *ptr_sum3     ; Force result [R+303] to be a pointer via dereferencing
            output('o [R+304])            ; Force [R+304] to be a char

            halt
            "#,
        )
        .unwrap();
    println!(
        "Pretty printed model with types (V3):\n{}",
        pretty_print_types(&ctx.model)
    );

    // Test case 4: [R+301] is an integer, [R+303] is a pointer, so [R+300] must be a pointer.
    // Test case 3: [R+301] is an integer, [R+300] must be a pointer, result is pointer
    assert_marker_type!(ctx, 'g', Type::pointer(Type::Char));
    assert_marker_type!(ctx, 'h', Type::Int);
    assert_marker_type!(ctx, 'i', Type::Int);
    assert_marker_type!(ctx, 's', Type::pointer(Type::Char));
    assert_marker_type!(ctx, 'o', Type::Char);
}

#[test]
fn test_pointer_arithmetic_case5() {
    let ctx = TypeInferenceComplete::test_context(
        r#"
            R += 1000

            ; Test case 5: When the result is a pointer, and one operand is a pointer,
            ; the other operand must be inferred as an integer
            [R+400] = 4000           ; Just a value that will become a pointer
            ptr_d = 'j [R+400]             ; Store in ptr_d
            [R+401] = *ptr_d         ; Force ptr_d to be a pointer through dereferencing
            output('k [R+401])             ; Force [R+401] to be a char

            ; Define an operand we want to test (with marker to check its inferred type)
            [R+402] = 30             ; This value should be inferred as an integer

            ; Addition where we'll force the result to be a pointer
            [R+403] = ptr_d + 'l [R+402]  ; The addition (with marker on result)
            ptr_sum4 = 't [R+403]          ; Store for dereferencing
            [R+404] = *ptr_sum4      ; Force result to be a pointer
            output('p [R+404])             ; Force [R+404] to be a char

            halt
            "#,
    )
    .unwrap();
    println!(
        "Pretty printed model with types (V3):\n{}",
        pretty_print_types(&ctx.model)
    );

    // Test case 4: When one operand and result are known to be pointers,
    // the other operand must be inferred as an integer
    assert_marker_type!(ctx, 'j', Type::pointer(Type::Char)); // Base address
    assert_marker_type!(ctx, 'k', Type::Char); // Dereferenced result
    assert_marker_type!(ctx, 'l', Type::Int); // This should be inferred as an integer
    assert_marker_type!(ctx, 't', Type::pointer(Type::Char)); // Result is pointer
    assert_marker_type!(ctx, 'p', Type::Char); // Dereferenced result
}

#[test]
fn test_pointer_arithmetic_case6() {
    let ctx = TypeInferenceComplete::test_context(
        r#"
            R += 1000

            ; Test case 6: When the result is a pointer, and one operand is a pointer,
            ; the other operand must be inferred as an integer. Oppsite operands to case 5.
            [R+400] = 4000           ; Just a value that will become a pointer
            ptr_d = 'j [R+400]             ; Store in ptr_d
            [R+401] = *ptr_d         ; Force ptr_d to be a pointer through dereferencing
            output('k [R+401])             ; Force [R+401] to be a char

            ; Define an operand we want to test (with marker to check its inferred type)
            [R+402] = 30             ; This value should be inferred as an integer

            ; Addition where we'll force the result to be a pointer
            [R+403] = 'l [R+402] + ptr_d; The addition (with marker on result)
            ptr_sum4 = 't [R+403]          ; Store for dereferencing
            [R+404] = *ptr_sum4      ; Force result to be a pointer
            output('p [R+404])             ; Force [R+404] to be a char

            halt
            "#,
    )
    .unwrap();
    println!(
        "Pretty printed model with types (V3):\n{}",
        pretty_print_types(&ctx.model)
    );

    // Test case 4: When one operand and result are known to be pointers,
    // the other operand must be inferred as an integer
    assert_marker_type!(ctx, 'j', Type::pointer(Type::Char)); // Base address
    assert_marker_type!(ctx, 'k', Type::Char); // Dereferenced result
    assert_marker_type!(ctx, 'l', Type::Int); // This should be inferred as an integer
    assert_marker_type!(ctx, 't', Type::pointer(Type::Char)); // Result is pointer
    assert_marker_type!(ctx, 'p', Type::Char); // Dereferenced result
}

#[test]
fn test_pointer_arithmetic_case7() {
    let ctx = TypeInferenceComplete::test_context(
        r#"
            R += 1000

            ; Test case 7: When the result is an int, all other operands must be ints.
            [R+700] = 100
            [R+701] = 20
            [R+702] = 'b [R+701] + 'a [R+700]
            'd [R+703] = 'c [R+702] * 12
            halt
            "#,
    )
    .unwrap();
    println!(
        "Pretty printed model with types (V3):\n{}",
        pretty_print_types(&ctx.model)
    );

    // Test case 4: When one operand and result are known to be pointers,
    // the other operand must be inferred as an integer
    assert_marker_type!(ctx, 'a', Type::Int);
    assert_marker_type!(ctx, 'b', Type::Int);
    assert_marker_type!(ctx, 'c', Type::Int);
    assert_marker_type!(ctx, 'd', Type::Int);
}

#[test]
fn test_infers_func_types_based_on_main_usage() {
    let assembly = r#"
            ; Main function
            R += 100           ; Initial R adjustment for main function
            [R+1] = 5          ; Set argument
            [R] = @return_addr ; Set return address
            goto @func         ; Call function
            return_addr:
            output([R+1])      ; Output return value
            halt

            ; Function that adds 5 to its input
            func:
            R += 3             ; Adjust stack for local variables
            [R-2] = [R-2] * 3
            'a [R-2] = 'b [R-2] + 5  ; result = arg + 5
            R -= 3             ; Restore stack
            goto [R]           ; Return
        "#;
    let ctx = TypeInferenceComplete::test_context(assembly).unwrap();
    println!(
        "Pretty printed model with types (V3):\n{}",
        pretty_print_types(&ctx.model)
    );
    ctx.model.type_inference_result().print_all_type_bounds();
    assert_marker_type!(ctx, 'a', Type::Char);
    assert_marker_type!(ctx, 'b', Type::Int);
}

#[test]
fn test_fn_pointer_args_inferred() {
    let ctx = TypeInferenceComplete::test_context(
        r#"
            R += 1000
            [R+1] = 2000
            [R+2] = 'a @f1
            [R] = @c1
            goto @takes_pointer
            c1:

            [R+1] = 3000
            [R+2] = @f2
            [R] = @c2
            goto @takes_pointer
            c2:

            [R+1] = 4000
            [R+2] = @f3
            [R] = @c3
            goto @takes_pointer
            c3:
            halt

        takes_pointer:  ; R-5: Pointer(int)  to pass, [R-4]: Functin(Pointer(Int), Int) -> ()
            R += 6
            [R-1] = 3
            [R-2] = 4
            ; ptr4 = [R-5]
            ; [6000] = *ptr4
            [R-2] = [R-2] * [R-1]
            [R-2] = 'b [R-5] + [R-2]
            [R+1] = 'c [R-5]
            [R+2] = 17
            [R] = @tpret
            goto 'd [R-4]
        tpret:
            R-=6
            goto [R]


        f1:
            R += 2
            ptr1 = 'e [R-1]
            output *ptr1
            R -= 2
            goto [R]

        f2:
            R += 2
            ptr2 = 'f [R-1]
            if *ptr2 goto @fret2
            output 35
        fret2:
            R -= 2
            goto [R]

        f3:
            R += 3
            ptr3 = 'g [R-2]
            [R-2] = *ptr3
            [R-2] = [R-2] * 7
            R -= 3
            goto [R]
            "#,
    )
    .unwrap();
    println!(
        "Pretty printed model with types (V3):\n{}",
        pretty_print_types(&ctx.model)
    );
    ctx.model.type_inference_result().print_all_type_bounds();

    // 'a' is the function pointer @f1, which has signature (Pointer<Char>) -> ()
    assert_marker_type!(
        ctx,
        'a',
        Type::function(Type::tuple(&[Type::pointer(Type::Char)]), Type::tuple(&[]))
    );

    // 'b' and 'c' are the first parameter to takes_pointer, which should be Pointer<Generic>
    // We can't directly assert on generics, so let's check they are pointers
    let b_type = get_marker_type_from_model(&ctx.model, 'b').unwrap();
    let c_type = get_marker_type_from_model(&ctx.model, 'c').unwrap();
    assert!(
        matches!(b_type, Type::Pointer(_)),
        "Expected 'b' to be a Pointer type, got {:?}",
        b_type
    );
    assert!(
        matches!(b_type.pointee(), Some(Type::Generic(_))),
        "Expected 'b' to be a Pointer to a generic type, got {:?}",
        b_type
    );
    assert!(
        matches!(c_type, Type::Pointer(_)),
        "Expected 'c' to be a Pointer type, got {:?}",
        c_type
    );
    assert!(
        matches!(c_type.pointee(), Some(Type::Generic(_))),
        "Expected 'c' to be a Pointer to a generic type, got {:?}",
        c_type
    );

    // 'd' is the second parameter to takes_pointer, which should be Function(Pointer<Generic>) -> ()
    let d_type = get_marker_type_from_model(&ctx.model, 'd').unwrap();
    if let Type::Function { params, returns } = &d_type {
        // Check params
        if let Type::Tuple(param_types) = params.as_ref() {
            assert_eq!(
                param_types.len(),
                1,
                "Function 'd' params: expected 1, got {} in {:?}\nFull d_type: {:?}",
                param_types.len(),
                params,
                d_type
            );

            // Check first parameter: Pointer(Generic)
            let first_param_type = &param_types[0];
            if let Type::Pointer(pointee_type) = first_param_type {
                if !matches!(pointee_type.as_ref(), Type::Generic(_)) {
                    panic!(
                            "Function 'd' first param: expected Pointer(Generic), got Pointer({:?})\nFull d_type: {:?}",
                            pointee_type.as_ref(), // Use as_ref() for content of Box
                            d_type
                        );
                }
            } else {
                panic!(
                    "Function 'd' first param: expected Pointer, got {:?}\nFull d_type: {:?}",
                    first_param_type, d_type
                );
            }
        } else {
            panic!(
                "Function 'd' params: expected Tuple, got {:?}\nFull d_type: {:?}",
                params, d_type
            );
        }

        // Check returns
        if let Type::Tuple(return_types) = returns.as_ref() {
            assert_eq!(
                return_types.len(),
                0,
                "Function 'd' returns: expected Tuple([]), got {:?} (len {})\nFull d_type: {:?}",
                returns,
                return_types.len(),
                d_type
            );
        } else {
            panic!(
                "Function 'd' returns: expected Tuple, got {:?}\nFull d_type: {:?}",
                returns, d_type
            );
        }
    } else {
        panic!("Expected 'd' to be a Function type, got {:?}", d_type);
    }

    // 'e' is the parameter in f1, should be Pointer<Char>
    assert_marker_type!(ctx, 'e', Type::pointer(Type::Char));

    // 'f' is the parameter in f2, should be Pointer<Truthy>
    assert_marker_type!(ctx, 'f', Type::pointer(Type::Truthy));

    // 'g' is the parameter in f3, should be Pointer<Int>
    assert_marker_type!(ctx, 'g', Type::pointer(Type::Int));
}
