// Ported from v2/listeners/data_flow_analyzer.rs tests
#[cfg(test)]
mod tests {
    use crate::disasm::{
        parser,
        test_utils::init_logging,
        v3::{
            control_flow::ControlFlowGraphBuilder, // v3 CFG Builder
            data_flow::{analyzer::DataFlowAnalyzer, block::OriginationPoint, DataFlowBlock},
            id_types::{BlockId, PointerId},     // v3 IDs
            image_scanner::ImageScanner,        // v3 Image Scanner
            lir::{Expression, MemoryReference}, // v3 LIR types
            model::{DataFlowComplete, Model},   // v3 Model states
        },
    };
    use itertools::Itertools;
    use pretty_assertions::assert_eq;
    use std::collections::{HashMap, HashSet};

    // Helper to setup model, run CFG build, and then data flow analysis using v3 pipeline
    fn setup_and_analyze(assembly_code: &str) -> Model<DataFlowComplete> {
        init_logging();
        let binary = parser::compile(assembly_code);
        let initial_model = Model::from_binary(binary);

        // v3 Pipeline
        // Pass binary by value (ownership)
        let image_scanned = ImageScanner::run(initial_model).expect("Image scanning failed");
        let cfg_built = ControlFlowGraphBuilder::run(image_scanned).expect("CFG building failed");
        

        DataFlowAnalyzer::run(cfg_built).expect("Data flow analysis failed") // Return model with DataFlow results
    }

    // Helper to get DataFlowBlock for assertions
    fn get_flow(model: &Model<DataFlowComplete>, block_id: BlockId) -> &DataFlowBlock {
        // Access CFG result to find the function ID for the block
        model
            .find_block(&block_id)
            .map(|b| b.data_flow())
            .unwrap_or_else(|| panic!("Could not find function ID for block {block_id:?}"))
    }

    #[test]
    fn test_simple_sequence() {
        let model = setup_and_analyze(
            r#"
            ; func @ 0
            R += 2          ; 0
            [100] = 5       ; 2 ; Def A: [100]=5 (@0, i2)
            [101] = [100]   ; 6 ; Use A, Def B: [101]=[100] (@0, i6)
            output [101]    ; 10; Use B
            R -= 2          ; 12; Block 12 starts here
            goto [R]        ; 14
            "#,
        );

        let block0_id = BlockId::from(0);
        let block12_id = BlockId::from(12); // Return block

        let flow0 = get_flow(&model, block0_id);
        let flow12 = get_flow(&model, block12_id);

        // --- Block 0 ---
        // GEN/USE
        assert_eq!(flow0.gen.len(), 2, "GEN length should be 2");
        assert!(
            flow0.gen.contains_key(&MemoryReference::Global(100)),
            "GEN should contain [100]"
        );
        assert!(
            flow0.gen.contains_key(&MemoryReference::Global(101)),
            "GEN should contain [101]"
        );
        assert!(flow0.use_before_def.is_empty(), "USE @ B0");

        // Check that defs_out contains definitions for [100] and [101] and kills stack inputs
        let defs_out0_kinds: HashSet<_> =
            flow0.defs_out.iter().map(|def| def.kind.clone()).collect();
        assert!(
            defs_out0_kinds.contains(&MemoryReference::Global(100)),
            "DefsOut should contain [100]"
        );
        assert!(
            defs_out0_kinds.contains(&MemoryReference::Global(101)),
            "DefsOut should contain [101]"
        );
        assert!(
            !defs_out0_kinds.contains(&MemoryReference::StackRelative(-1)),
            "DefsOut should NOT contain [R-1]"
        );
        assert!(
            !defs_out0_kinds.contains(&MemoryReference::StackRelative(-2)),
            "DefsOut should NOT contain [R-2]"
        );
        assert_eq!(flow0.defs_out.len(), 2, "DefsOut @ B0 length");

        // --- Block 12 (Return) ---
        // GEN/USE
        assert!(flow12.gen.is_empty(), "GEN @ B12");
        assert!(flow12.use_before_def.is_empty(), "USE @ B12"); // goto [R] uses R, but R is special

        // Reaching Defs
        let defs_in12_kinds: HashSet<_> =
            flow12.defs_in.iter().map(|def| def.kind.clone()).collect();
        assert!(
            defs_in12_kinds.contains(&MemoryReference::Global(100)),
            "DefsIn @ B12 should contain [100]"
        );
        assert!(
            defs_in12_kinds.contains(&MemoryReference::Global(101)),
            "DefsIn @ B12 should contain [101]"
        );
        assert_eq!(flow12.defs_in.len(), 2, "DefsIn @ B12 length");

        // DefsOut should be the same as DefsIn for this block
        assert_eq!(flow12.defs_out, flow12.defs_in, "DefsOut @ B12");

        // Liveness
        assert!(flow12.live_out.is_empty(), "LiveOut @ B12"); // Nothing live after return
                                                              // Check live_in for block 0 (entry) - should be empty as nothing is used before defined
        assert!(flow0.live_in.is_empty(), "LiveIn @ B0 should be empty");
        // Check live_in for block 12 (return) - should be empty as goto [R] is special
        assert!(flow12.live_in.is_empty(), "LiveIn @ B12 should be empty");
    }

    #[test]
    fn test_if_else() {
        let model = setup_and_analyze(
            r#"
             ; func @ 0
             R += 3                ; 0
             [100] = 1             ; 2  ; Def A (@0, i2)
             if [100] goto @true   ; 6  ; Use A
             ; false branch @ 9
             [101] = 10            ; 9  ; Def B (@9, i9)
             goto @merge           ; 13
             ; true branch @ 16
             true:
             [101] = 20            ; 16 ; Def C (@16, i16)
             ; merge block @ 20
             merge:
             output [101]          ; 20 ; Use B or C
             R -= 3                ; 22 ; Return block starts
             goto [R]              ; 24
             "#,
        );

        let block0_id = BlockId::from(0);
        let block9_id = BlockId::from(9); // False branch
        let block16_id = BlockId::from(16); // True branch
        let block20_id = BlockId::from(20); // Merge block
        let block22_id = BlockId::from(22); // Return block

        let _flow0 = get_flow(&model, block0_id);
        let flow9 = get_flow(&model, block9_id);
        let flow16 = get_flow(&model, block16_id);
        let flow20 = get_flow(&model, block20_id);
        let flow22 = get_flow(&model, block22_id);

        // --- Check Defs reaching merge block (Block 20) ---
        let defs_in20_kinds: HashSet<_> =
            flow20.defs_in.iter().map(|def| def.kind.clone()).collect();
        assert!(
            defs_in20_kinds.contains(&MemoryReference::Global(100)),
            "DefsIn @ B20 should contain [100]"
        );
        assert!(
            defs_in20_kinds.contains(&MemoryReference::Global(101)),
            "DefsIn @ B20 should contain [101]"
        );

        // Check that there are definitions for [101] from both branches
        let defs_in20_block_ids_for_101: HashSet<_> = flow20
            .defs_in
            .iter()
            .filter(|def| def.kind == MemoryReference::Global(101))
            .map(|def| def.block_id)
            .collect();
        assert!(
            defs_in20_block_ids_for_101.contains(&block9_id),
            "DefsIn @ B20 should contain [101] from block 9"
        );
        assert!(
            defs_in20_block_ids_for_101.contains(&block16_id),
            "DefsIn @ B20 should contain [101] from block 16"
        );

        // --- Check USE in merge block (Block 20) ---
        assert_eq!(
            flow20
                .use_before_def
                .keys()
                .cloned()
                .collect::<HashSet<_>>(),
            [MemoryReference::Global(101)].iter().cloned().collect(),
            "USE @ B20"
        );
        assert!(flow20.gen.is_empty(), "GEN @ B20"); // Output doesn't generate defs

        // --- Check GEN in branches ---
        assert!(
            flow9.gen.contains_key(&MemoryReference::Global(101)),
            "GEN @ B9 should contain [101]"
        );
        assert!(
            flow16.gen.contains_key(&MemoryReference::Global(101)),
            "GEN @ B16 should contain [101]"
        );

        // --- Check Defs reaching branches ---
        // Only Def A ([100]) reaches both branches from block 0
        let defs_in9_kinds: HashSet<_> = flow9.defs_in.iter().map(|def| def.kind.clone()).collect();
        let defs_in16_kinds: HashSet<_> =
            flow16.defs_in.iter().map(|def| def.kind.clone()).collect();

        assert!(
            defs_in9_kinds.contains(&MemoryReference::Global(100)),
            "DefsIn @ B9 should contain [100]"
        );
        assert!(
            !defs_in9_kinds.contains(&MemoryReference::Global(101)),
            "DefsIn @ B9 should not contain [101]"
        );

        assert!(
            defs_in16_kinds.contains(&MemoryReference::Global(100)),
            "DefsIn @ B16 should contain [100]"
        );
        assert!(
            !defs_in16_kinds.contains(&MemoryReference::Global(101)),
            "DefsIn @ B16 should not contain [101]"
        );

        // --- Check Defs out of merge block (Block 20) ---
        // Defs from branches should reach, Def A also. Output generates nothing new.
        let defs_out20_kinds: HashSet<_> =
            flow20.defs_out.iter().map(|def| def.kind.clone()).collect();
        assert!(
            defs_out20_kinds.contains(&MemoryReference::Global(100)),
            "DefsOut @ B20 should contain [100]"
        );
        assert!(
            defs_out20_kinds.contains(&MemoryReference::Global(101)),
            "DefsOut @ B20 should contain [101]"
        );

        // --- Check Defs into return block (Block 22) ---
        let defs_in22_kinds: HashSet<_> =
            flow22.defs_in.iter().map(|def| def.kind.clone()).collect();
        assert!(
            defs_in22_kinds.contains(&MemoryReference::Global(100)),
            "DefsIn @ B22 should contain [100]"
        );
        assert!(
            defs_in22_kinds.contains(&MemoryReference::Global(101)),
            "DefsIn @ B22 should contain [101]"
        );

        // --- Liveness ---
        assert!(flow22.live_out.is_empty(), "LiveOut @ B22");
        assert!(flow22.live_in.is_empty(), "LiveIn @ B22");

        // Check live_in for merge block (20) - should contain [101] used by output
        assert!(
            flow20.live_in.contains_key(&MemoryReference::Global(101)),
            "LiveIn @ B20 should contain [101]"
        );
        assert_eq!(flow20.live_in.len(), 1, "LiveIn @ B20 length");
        // assert!(flow9.live_in.contains_key(&MemoryReference::Global(100)), "LiveIn @ B9 should contain [100]"); // Removed: Added in v3, incorrect assertion
    }

    #[test]
    fn test_loop() {
        let model = setup_and_analyze(
            r#"
             ; func @ 0
             R += 2          ; 0
             [100] = 5       ; 2  ; Def A (@0, i2)
             loop_start:         ; block @ 6
             output [100]    ; 6  ; Use A or C
             [100] = [100] + -1 ; 8  ; Use A or C, Def C (@6, i8)
             if [100] goto @loop_start ; 12 ; Use C
             ; exit block @ 15
             R -= 2          ; 15 ; Return block starts
             goto [R]        ; 17
             "#,
        );

        let block0_id = BlockId::from(0); // Init
        let block6_id = BlockId::from(6); // Loop body + condition
        let block15_id = BlockId::from(15); // Exit/Return block

        let flow0 = get_flow(&model, block0_id);
        let flow6 = get_flow(&model, block6_id);
        let flow15 = get_flow(&model, block15_id);

        // --- Check Defs reaching loop header/body (Block 6) ---
        // Should receive Def A from block 0 AND Def C from loop back edge
        let defs_in6_sources: HashSet<_> = flow6
            .defs_in
            .iter()
            .filter(|def| def.kind == MemoryReference::Global(100))
            .map(|def| {
                (
                    def.block_id,
                    matches!(def.source, OriginationPoint::Instruction(_)),
                )
            })
            .collect();

        // Should have a definition from block 0 and from block 6 itself (loop back edge)
        assert!(
            defs_in6_sources.contains(&(block0_id, true)),
            "DefsIn @ B6 should contain [100] from block 0"
        );
        assert!(
            defs_in6_sources.contains(&(block6_id, true)),
            "DefsIn @ B6 should contain [100] from block 6 (loop back edge)"
        );

        // --- Check USE in loop block (Block 6) ---
        // output reads [100], addition reads [100], if reads [100]
        assert_eq!(
            flow6.use_before_def.keys().cloned().collect::<HashSet<_>>(),
            [MemoryReference::Global(100)].iter().cloned().collect(),
            "USE @ B6"
        );

        // --- Check GEN in loop block (Block 6) ---
        // The last write to [100] is in this block
        assert!(
            flow6.gen.contains_key(&MemoryReference::Global(100)),
            "GEN @ B6 should contain [100]"
        );

        // --- Check Defs out of loop block (Block 6) ---
        // This is DefsIn(6) - KilledDefs(6) U GenDefs(6)
        // Should only contain the definition from this block
        let defs_out6_blocks: HashSet<_> = flow6
            .defs_out
            .iter()
            .filter(|def| def.kind == MemoryReference::Global(100))
            .map(|def| def.block_id)
            .collect();

        assert_eq!(
            defs_out6_blocks,
            [block6_id].iter().cloned().collect(),
            "DefsOut @ B6 should only contain [100] from block 6"
        );

        // --- Check Defs into exit block (Block 15) ---
        // Comes from the 'if' condition failing in block 6. Should receive DefsOut(6).
        let defs_in15_blocks: HashSet<_> = flow15
            .defs_in
            .iter()
            .filter(|def| def.kind == MemoryReference::Global(100))
            .map(|def| def.block_id)
            .collect();

        assert_eq!(
            defs_in15_blocks,
            [block6_id].iter().cloned().collect(),
            "DefsIn @ B15 should only contain [100] from block 6"
        );

        // --- Liveness ---
        assert!(flow15.live_out.is_empty(), "LiveOut @ B15");
        assert!(flow15.live_in.is_empty(), "LiveIn @ B15");

        // Check live_in for loop block (6) - should contain [100] (used by output, add, if)
        assert!(
            flow6.live_in.contains_key(&MemoryReference::Global(100)),
            "LiveIn @ B6 should contain [100]"
        );
        assert_eq!(flow6.live_in.len(), 1, "LiveIn @ B6 length");

        // Check live_in for entry block (0) - should be empty as [100] is defined before use
        assert!(flow0.live_in.is_empty(), "LiveIn @ B0 should be empty");
    }

    #[test]
    fn test_function_call_return_values() {
        let model = setup_and_analyze(
            r#"
                    ; main @ 0
                    R += 3          ; 0
                    [100] = 50      ; 2  ; Def A: [100]=50 (@0, i2)
                    [R+1] = [100]   ; 6  ; Def B: [R+1]=[100] (@0, i6)
                    [R+2] = 99      ; 10 ; Def C: [R+2]=99 (@0, i10)
                    [R] = @ret      ; 14 ; Setup return addr
                    goto @callee    ; 18 ; Call callee (func address 30, immediate)
                    ret:                ; block @ 21
                    output [R+1]    ; 21 ; Use RetDef D
                    output [R+2]    ; 23 ; Use RetDef E
                    R -= 3          ; 25 ; Return block starts
                    goto [R]        ; 27

                    ; callee @ 30
                    callee:
                    R += 5          ; 30 ; Stack size 2 (args) + 3 (locals) = 5
                    [R-3] = [R-3] + 1 ; 32 ; Modify arg1 ([R+1]->[R-3]), store in ret slot 1 ([R-3])
                    [R-4] = [R-4] * 2 ; 36 ; Modify arg2 ([R+2]->[R-4]), store in ret slot 2 ([R-4])
                                           ; Note: callee writes to R-3 and R-4 which map to caller's R+1 and R+2
                    R -= 5          ; 40 ; Return block starts
                    goto [R]        ; 42
                    "#,
        );

        let block0_id = BlockId::from(0); // main entry + call setup
        let block21_id = BlockId::from(21); // main return block
        let block25_id = BlockId::from(25); // main actual return sequence
        let block30_id = BlockId::from(30); // callee entry
        let block40_id = BlockId::from(40); // callee return

        for func in model.image_scanner_result().recognized_functions.values() {
            println!("function {}", func.span.start);
            for inst in &func.instructions {
                println!("{:8}  {}", inst.span.start, inst);
            }
            println!();
        }

        let flow0 = get_flow(&model, block0_id);
        let flow21 = get_flow(&model, block21_id);
        let flow25 = get_flow(&model, block25_id);
        let flow30 = get_flow(&model, block30_id);
        let flow40 = get_flow(&model, block40_id);

        // --- Check USE in return block (Block 21) ---
        // This determines potential_returns for the call from block 0
        assert_eq!(
            flow21.use_before_def.keys().sorted().collect::<Vec<_>>(),
            [
                MemoryReference::StackRelative(1),
                MemoryReference::StackRelative(2)
            ]
            .iter()
            .sorted()
            .collect::<Vec<_>>(),
            "USE @ B21"
        );

        // --- Check Defs reaching return block (Block 21) ---
        let defs_in21_kinds: HashSet<_> =
            flow21.defs_in.iter().map(|def| def.kind.clone()).collect();

        // Should contain [100] but not [R+1] or [R+2] which are killed by the call
        assert!(
            defs_in21_kinds.contains(&MemoryReference::Global(100)),
            "DefsIn @ B21 should contain [100]"
        );
        assert!(
            !defs_in21_kinds.contains(&MemoryReference::StackRelative(1)),
            "DefsIn @ B21 should not contain [R+1] from before call"
        );
        assert!(
            !defs_in21_kinds.contains(&MemoryReference::StackRelative(2)),
            "DefsIn @ B21 should not contain [R+2] from before call"
        );

        // Check for function return info
        assert!(
            !flow21.function_returns_in.is_empty(),
            "Block 21 should have function returns"
        );
        let func_call = flow21.function_returns_in.iter().next().unwrap();
        assert_eq!(func_call.calling_block, block0_id);
        assert_eq!(
            func_call.function_addr,
            Expression::Constant(30),
            "Function address should be 30"
        );
        assert_eq!(func_call.return_block, block21_id);

        // --- Check Defs out of return block (Block 21) ---
        // Should be same as DefsIn, since output doesn't kill/gen memory defs
        assert_eq!(flow21.defs_out, flow21.defs_in, "DefsOut @ B21");

        // --- Check Defs into actual return sequence (Block 25) ---
        assert_eq!(flow25.defs_in, flow21.defs_out, "DefsIn @ B25");

        // --- Check Call Site Info (Block 0) ---
        assert!(
            flow0.return_values_accessed.is_some(),
            "Call site info should be present in block 0"
        );
        let return_values_accessed = flow0.return_values_accessed.as_ref().unwrap();

        // Should have return values accessed for [R+1] and [R+2]
        assert!(
            return_values_accessed.contains_key(&1),
            "Call site should record [R+1] as accessed"
        );
        assert!(
            return_values_accessed.contains_key(&2),
            "Call site should record [R+2] as accessed"
        );

        // --- Liveness ---
        assert!(flow25.live_out.is_empty(), "LiveOut @ B25");
        assert!(flow25.live_in.is_empty(), "LiveIn @ B25");

        // Check live_in for return block (21) - should contain [R+1] and [R+2] used by output
        assert!(
            flow21
                .live_in
                .contains_key(&MemoryReference::StackRelative(1)),
            "LiveIn @ B21 should contain [R+1]"
        );
        assert!(
            flow21
                .live_in
                .contains_key(&MemoryReference::StackRelative(2)),
            "LiveIn @ B21 should contain [R+2]"
        );
        assert_eq!(flow21.live_in.len(), 2, "LiveIn @ B21 length");

        // Check live_in for callee entry (30) - should contain [R-3] and [R-4] (parameters)
        assert!(
            flow30
                .live_in
                .contains_key(&MemoryReference::StackRelative(-3)),
            "LiveIn @ B30 should contain [R-3]"
        );
        assert!(
            flow30
                .live_in
                .contains_key(&MemoryReference::StackRelative(-4)),
            "LiveIn @ B30 should contain [R-4]"
        );
        assert_eq!(flow30.live_in.len(), 2, "LiveIn @ B30 length");

        // Check live_out for callee return block (40) - should contain [R-3] and [R-4] (return values)
        // marked as FunctionOutput
        assert!(
            flow40
                .live_out
                .get(&MemoryReference::StackRelative(-3))
                .is_some_and(|s| s.contains(&OriginationPoint::FunctionOutput)),
            "LiveOut @ B40 should contain [R-3] marked as FunctionOutput"
        );
        assert!(
            flow40
                .live_out
                .get(&MemoryReference::StackRelative(-4))
                .is_some_and(|s| s.contains(&OriginationPoint::FunctionOutput)),
            "LiveOut @ B40 should contain [R-4] marked as FunctionOutput"
        );
        assert_eq!(flow40.live_out.len(), 2, "LiveOut @ B40 length");
    }

    #[test]
    fn test_unused_write_killed() {
        let model = setup_and_analyze(
            r#"
                     ; func @ 0
                     R += 2          ; 0
                     [100] = 5       ; 2 ; Def A
                     [100] = 10      ; 6 ; Def B (kills A)
                     output [100]    ; 10; Use B
                     R -= 2          ; 12
                     goto [R]        ; 14
                     "#,
        );
        let block0_id = BlockId::from(0);
        let block12_id = BlockId::from(12); // Return block

        let flow0 = get_flow(&model, block0_id);
        let flow12 = get_flow(&model, block12_id);

        // GEN should only contain the *last* write
        assert_eq!(flow0.gen.len(), 1, "GEN should only contain one entry");
        assert!(
            flow0.gen.contains_key(&MemoryReference::Global(100)),
            "GEN should contain [100]"
        );
        let (_, (gen_instr_id, _)) = flow0.gen.iter().next().unwrap();
        // Instruction [100] = 10 is the second instruction in the block (index 1)
        // Let's find its actual ID
        let block0_instrs = model
            .find_block(&block0_id)
            .unwrap()
            .low_instructions()
            .iter()
            .collect_vec();
        let expected_gen_instr_id = block0_instrs[1].id; // ID of '[100] = 10'
        assert_eq!(
            *gen_instr_id, expected_gen_instr_id,
            "GEN should point to the second write instruction"
        );

        // Defs Out should only contain one definition for [100]
        let defs_out0_for_100: Vec<_> = flow0
            .defs_out
            .iter()
            .filter(|def| def.kind == MemoryReference::Global(100))
            .collect();

        assert_eq!(
            defs_out0_for_100.len(),
            1,
            "DefsOut @ B0 should contain exactly one definition for [100]"
        );
        assert_eq!(
            defs_out0_for_100[0].block_id, block0_id,
            "DefsOut @ B0 should contain definition from block 0"
        );
        assert_eq!(
            defs_out0_for_100[0].source,
            OriginationPoint::Instruction(expected_gen_instr_id),
            "DefsOut @ B0 source should be the second write"
        );

        // Defs In for return block should only contain one definition for [100]
        let defs_in12_for_100: Vec<_> = flow12
            .defs_in
            .iter()
            .filter(|def| def.kind == MemoryReference::Global(100))
            .collect();

        assert_eq!(
            defs_in12_for_100.len(),
            1,
            "DefsIn @ B12 should contain exactly one definition for [100]"
        );
        assert_eq!(
            defs_in12_for_100[0].block_id, block0_id,
            "DefsIn @ B12 should contain definition from block 0"
        );
        assert_eq!(
            defs_in12_for_100[0].source,
            OriginationPoint::Instruction(expected_gen_instr_id),
            "DefsIn @ B12 source should be the second write"
        );

        // --- Liveness ---
        assert!(flow12.live_out.is_empty(), "LiveOut @ B12");
        assert!(flow12.live_in.is_empty(), "LiveIn @ B12");
    }

    #[test]
    fn test_multiple_function_calls() {
        let model = setup_and_analyze(
            r#"
            ; main @ 0
            R += 3              ; 0
            [R] = 9             ; 2 ; Set return for func0 call
            goto @func0         ; 6 ; Call func0 (addr 97)
            ; block @ 9 (return from func0)
            if ![1129] goto @cont  ; 9 ; Check global flag
            ; block @ 12
            [R+1] = 316         ; 12 ; Arg for func2
            [R] = 23            ; 16 ; Set return for func2 call
            goto @func2         ; 20 ; Call func2 (addr 115)
            ; block @ 23 (return from func2)
            goto 92             ; 23 ; Jump to exit
            cont:                   ; block @ 26
            [R-1] = 0           ; 26 ; Init loop counter [R-1] (local var)
            ; block @ 30 (loop start)
            p36 = [R-1] + 0     ; 30 ; p36 = loop counter address
            [R+1] = *p36        ; 34 ; Arg for func3 = *p36 (deref loop counter addr - likely error in original code?)
                                    ; Let's assume it meant to use the counter value, not its address.
                                    ; For analysis, we track the pointer p36.
            [R+2] = 0           ; 38 ; Arg 2 for func3
            [R+3] = 0           ; 42 ; Arg 3 for func3
            [R] = 53            ; 46 ; Set return for func3 call
            goto @func3         ; 50 ; Call func3 (addr 124)
            ; block @ 53 (return from func3)
            if ![R+1] goto 70   ; 53 ; Check func3 return value [R+1]
            ; block @ 56
            p66 = [R-1] + 40    ; 56 ; p66 = loop counter addr + 40
            [R] = 67            ; 60 ; Set return for indirect call
            goto *p66           ; 64 ; Indirect call via p66 (likely func1 @ 106 if counter was 66?)
            ; block @ 67 (return from indirect call)
            goto 92             ; 67 ; Jump to exit
            ; block @ 70 (loop increment)
            [R-1] = [R-1] + 1   ; 70 ; Increment loop counter
            [R-2] = [R-1] < 7   ; 74 ; Check loop condition [R-2] (local var)
            if [R-2] goto 30    ; 78 ; Loop back if counter < 7
            ; block @ 81
            [R+1] = 177         ; 81 ; Arg for func2
            [R] = 92            ; 85 ; Set return for func2 call
            goto @func2         ; 89 ; Call func2 (addr 115)
            ; block @ 92 (return from func2 OR exit path)
            R += -3             ; 92 ; Adjust R before final return
            goto [R]            ; 94 ; Return to caller of main

            func0:              ; func @ 97
            R += 2              ; 97 ; Stack size 1 (arg) + 1 (local) = 2
            output [R-1]        ; 99 ; Output arg [R-1]
            R -= 2              ; 101
            goto [R]            ; 103

            func1:              ; func @ 106 (Potentially called indirectly)
            R += 2              ; 106 ; Stack size 1 (arg) + 1 (local) = 2
            output [R-1]        ; 108 ; Output arg [R-1]
            R -= 2              ; 110
            goto [R]            ; 112

            func2:              ; func @ 115
            R += 2              ; 115 ; Stack size 1 (arg) + 1 (local) = 2
            output [R-1]        ; 117 ; Output arg [R-1]
            R -= 2              ; 119
            goto [R]            ; 121

            func3:              ; func @ 124
            R += 5              ; 124 ; Stack size 3 (args) + 2 (locals) = 5
            output [R-1]        ; 126 ; Output arg1 [R-1]
            [R-1] = [R-2] + [R-3] ; 128 ; Return value [R-1] = arg2 + arg3
            R -= 5              ; 132
            goto [R]            ; 134
        "#,
        );

        // --- Function Return Propagation Checks ---

        // Helper to check if a block's function_returns_in contains a call originating from `calling_block` to `func_addr`
        let check_returns_in = |model: &Model<DataFlowComplete>,
                                block_id: BlockId,
                                calling_block: BlockId,
                                func_addr: i128| {
            let flow = get_flow(model, block_id);
            flow.function_returns_in.iter().any(|fc| {
                fc.calling_block == calling_block
                    && fc.function_addr == Expression::Constant(func_addr)
            })
        };

        // Call to func0 (addr 97) from block 0, returns to block 9
        assert!(
            check_returns_in(&model, BlockId::from(9), BlockId::from(0), 97),
            "Block 9 should have returns from func0 call in block 0"
        );

        // Call to func2 (addr 115) from block 12, returns to block 23
        assert!(
            check_returns_in(&model, BlockId::from(23), BlockId::from(12), 115),
            "Block 23 should have returns from func2 call in block 12"
        );

        // Call to func3 (addr 124) from block 30, returns to block 53
        assert!(
            check_returns_in(&model, BlockId::from(53), BlockId::from(30), 124),
            "Block 53 should have returns from func3 call in block 30"
        );
        // This return should propagate through block 53 (if condition false) to block 70
        assert!(
            check_returns_in(&model, BlockId::from(70), BlockId::from(30), 124),
            "Block 70 should have returns from func3 call in block 30 (propagated)"
        );
        // And from 70 back to 30 (loop)
        assert!(
            check_returns_in(&model, BlockId::from(30), BlockId::from(30), 124),
            "Block 30 should have returns from func3 call in block 30 (looped back)"
        );
        // And from 70 to 81 (loop exit)
        assert!(
            check_returns_in(&model, BlockId::from(81), BlockId::from(30), 124),
            "Block 81 should have returns from func3 call in block 30 (loop exit)"
        );

        // Indirect call from block 56, returns to block 67
        // We can't easily check the exact function address, but check origin
        let flow67 = get_flow(&model, BlockId::from(67));
        assert!(
            flow67
                .function_returns_in
                .iter()
                .any(|fc| fc.calling_block == BlockId::from(56)),
            "Block 67 should have returns from indirect call in block 56"
        );

        // Call to func2 (addr 115) from block 81, returns to block 92
        assert!(
            check_returns_in(&model, BlockId::from(92), BlockId::from(81), 115),
            "Block 92 should have returns from func2 call in block 81"
        );

        // --- Check Absence of Returns ---
        // Block 26 (cont:) should NOT have returns from func2 (call happens later)
        let flow26 = get_flow(&model, BlockId::from(26));
        assert!(
            !flow26
                .function_returns_in
                .iter()
                .any(|fc| fc.function_addr == Expression::Constant(115)),
            "Block 26 should NOT have returns from func2"
        );

        // --- Check Use Before Def for return value ---
        // Block 53 reads [R+1] which is a return value from func3
        let flow53 = get_flow(&model, BlockId::from(53));
        assert!(
            flow53
                .use_before_def
                .contains_key(&MemoryReference::StackRelative(1)),
            "Block 53 should have [R+1] in use_before_def as a return value from func3"
        );

        // --- Check Call Site Info ---
        // Block 30 calls func3, return is read in block 53 ([R+1])
        let flow30 = get_flow(&model, BlockId::from(30));
        assert!(
            flow30.return_values_accessed.is_some(),
            "Block 30 should have call site info"
        );
        assert!(
            flow30
                .return_values_accessed
                .as_ref()
                .unwrap()
                .contains_key(&1),
            "Call site info for block 30 should record access to [R+1]"
        );

        // Block 56 calls indirectly, no return read check possible here easily

        // Block 81 calls func2, no return read in block 92
        let flow81 = get_flow(&model, BlockId::from(81));
        assert_eq!(
            flow81.return_values_accessed,
            Some(HashMap::new()),
            "Call site info for block 81 should record no return access"
        );
    }

    #[test]
    fn test_deref_result_in_live_in() {
        // This test verifies that pointer dereferencing operations are correctly tracked
        // in the liveness analysis. When pointers are used or dereferenced later in the
        // program, they should appear in the live_in set of preceding blocks.
        let model = setup_and_analyze(
            r#"
            ; func @ 0
            R += 3              ; 0
            ptr1 = 2            ; 2  ; Define pointer 1 (at instr index 0 in block 0) -> PointerId(0)
            ptr2 = 4            ; 6  ; Define pointer 2 (at instr index 1 in block 0) -> PointerId(1)
            goto @below         ; 10
            below:              ; block @ 13
            [R+1] = [R-1]       ; 13 ; Stack memory operation (instr 0 in block 13)
            *ptr1 = 7           ; 17 ; Dereference and write to ptr1 (instr 1 in block 13)
            [R+2] = *ptr2       ; 21 ; Read from dereferenced ptr2 (instr 2 in block 13)
            R -= 3              ; 25 ; block @ 25
            goto [R]
            "#,
        );

        let block0_id = BlockId::from(0);
        let block13_id = BlockId::from(13);

        // Find the actual PointerIds created by the analysis for ptr1 and ptr2
        // They depend on the InstructionIds assigned during CFG building.
        let _block0_instrs = model.find_block(&block0_id).unwrap().low_instructions();
        // ptr1 = 2 is the first instruction ([100]=2), ptr2 = 4 is the second ([101]=4)
        // Assuming the LIR converter creates PointerIds based on the instruction ID writing to the pointer variable's memory location.
        // Let's find the instruction IDs for the assignments `[100]=2` and `[101]=4` which represent ptr1 and ptr2 definitions.
        // The assembly `ptr1 = 2` translates to `[mem_for_ptr1] = 2`. We need the ID of this instruction.
        // The LIR conversion might simplify this. Let's look at the LIR instructions directly.
        // The native code `ptr1 = 2` becomes `[100] = 2` (assuming ptr1 maps to 100).
        // The native code `ptr2 = 4` becomes `[101] = 4` (assuming ptr2 maps to 101).
        // The LIR `*ptr1 = 7` becomes `Assign { target: Deref(Pointer(ptr1_id)), src: Constant(7) }`
        // The LIR `[R+2] = *ptr2` becomes `Assign { target: StackRelative(2), src: Deref(Pointer(ptr2_id)) }`

        // Get the data flow information for the "below" block at address 13
        let flow13 = get_flow(&model, block13_id);

        // Check that pointers and dereferences are correctly marked as live at block entry,
        // mirroring the intent of the v2 test.

        // Check that at least one MemoryReference::Pointer is live_in (for ptr1 used in write, and ptr2 used in read)
        assert!(
            flow13
                .live_in
                .contains_key(&MemoryReference::Pointer(PointerId::from(20))),
            "At least one MemoryReference::Pointer should be live_in"
        );

        // This verifies that dereferenced ptr2 is in the live_in set
        // The expression represents *ptr2, where ptr2 is defined at instruction position 6
        // The data flow analyzer correctly identified that we need to read through ptr2
        assert!(
            flow13
                .live_in
                .contains_key(&MemoryReference::Deref(Box::new(Expression::Addressable(
                    MemoryReference::Pointer(PointerId::from(22))
                )))),
            "Dereferenced ptr2 should be in live_in as it's read at instruction 21"
        );
        // Also check [R-1] is live due to instruction '[R+1] = [R-1]'
        assert!(
            flow13
                .live_in
                .contains_key(&MemoryReference::StackRelative(-1)),
            "[R-1] should be in live_in due to use in instruction 13"
        );
    }
}
