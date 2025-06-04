use crate::disasm::{
    test_utils::TestContextBuilder,
    v3::{
        model::TypeInferenceComplete,
        type_inference::{type_inference_tests::assert_marker_type, Type},
    },
};

#[test]
fn test_harder_type_inference() {
    let ctx = TypeInferenceComplete::test_context(
        r#"
            R += 1000
            halt


            f2722:
                R += 5
                'a [5000] = 'a [R-4]
                [R+1] = 8888
                [R] = @ret1
                goto @f2763
                ret1:
                R -= 5
                goto [R]


            f2763:
                R += 2
                [R+1] = 'b 346
                [R+2] = 'c [R-1]
                [R] = @ret2
                goto [5000]
                ret2:
                R -= 1
                goto [R]

            takes_int_pointer_int:
                R += 4
                [R-3] = [R-3] * 5
                ptr = [R-2]
                [R-2] = *ptr
                [R-2] = [R-2] * 3
                R -= 4
                goto [R]

            calls_f2722_with_take_pointer:
                R += 1
                [R+1] = @takes_int_pointer_int
                [R] = @retc
                goto @f2722
                retc:
                R -= 1
                goto [R]
        "#,
    )
    .unwrap();
    assert_marker_type!(
        ctx,
        'a',
        Type::function(
            Type::tuple(&[Type::Int, Type::pointer(Type::Int)]),
            Type::tuple(&[]),
        )
    );
    assert_marker_type!(ctx, 'b', Type::Int);
    assert_marker_type!(ctx, 'c', Type::pointer(Type::Int));
}
