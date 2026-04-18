use std::collections::HashMap;

#[derive(Debug, Clone, Copy)]
pub enum Opcode {
    Add = 1,
    Mul = 2,
    Input = 3,
    Output = 4,
    JumpTrue = 5,
    JumpFalse = 6,
    Less = 7,
    Equal = 8,
    AdjustRelBase = 9,
    Halt = 99,
}

impl TryFrom<i128> for Opcode {
    type Error = String;

    fn try_from(value: i128) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Opcode::Add),
            2 => Ok(Opcode::Mul),
            3 => Ok(Opcode::Input),
            4 => Ok(Opcode::Output),
            5 => Ok(Opcode::JumpTrue),
            6 => Ok(Opcode::JumpFalse),
            7 => Ok(Opcode::Less),
            8 => Ok(Opcode::Equal),
            9 => Ok(Opcode::AdjustRelBase),
            99 => Ok(Opcode::Halt),
            _ => Err(format!("Invalid opcode: {value}")),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ParameterMode {
    Memory = 0,
    Immediate = 1,
    Relative = 2,
}

impl From<i128> for ParameterMode {
    fn from(value: i128) -> Self {
        match value {
            0 => ParameterMode::Memory,
            1 => ParameterMode::Immediate,
            2 => ParameterMode::Relative,
            _ => ParameterMode::Memory, // Default to memory mode for invalid values
        }
    }
}

pub struct IntcodeVm {
    memory: HashMap<usize, i128>,
    instruction_pointer: usize,
    relative_base: i128,
    input_queue: Vec<i128>,
    output_queue: Vec<i128>,
    halted: bool,
}

impl IntcodeVm {
    pub fn new(program: Vec<i128>) -> Self {
        let mut memory = HashMap::new();
        for (i, value) in program.into_iter().enumerate() {
            memory.insert(i, value);
        }

        Self {
            memory,
            instruction_pointer: 0,
            relative_base: 0,
            input_queue: Vec::new(),
            output_queue: Vec::new(),
            halted: false,
        }
    }

    pub fn get_memory(&self, address: usize) -> i128 {
        self.memory.get(&address).copied().unwrap_or(0)
    }

    pub fn set_memory(&mut self, address: usize, value: i128) {
        self.memory.insert(address, value);
    }

    pub fn get_relative_base(&self) -> i128 {
        self.relative_base
    }

    pub fn set_relative_base(&mut self, value: i128) {
        self.relative_base = value;
    }

    pub fn push_input(&mut self, value: i128) {
        self.input_queue.push(value);
    }

    pub fn pop_output(&mut self) -> Option<i128> {
        if self.output_queue.is_empty() {
            None
        } else {
            Some(self.output_queue.remove(0))
        }
    }

    pub fn get_outputs(&self) -> &[i128] {
        &self.output_queue
    }

    pub fn clear_outputs(&mut self) {
        self.output_queue.clear();
    }

    pub fn is_halted(&self) -> bool {
        self.halted
    }

    pub fn has_input(&self) -> bool {
        !self.input_queue.is_empty()
    }

    pub fn is_waiting_for_input(&self) -> bool {
        !self.halted && self.get_memory(self.instruction_pointer) % 100 == 3 && !self.has_input()
    }

    pub fn get_instruction_pointer(&self) -> usize {
        self.instruction_pointer
    }

    fn get_parameter_value(&self, param: i128, mode: ParameterMode) -> i128 {
        match mode {
            ParameterMode::Immediate => param,
            ParameterMode::Memory => self.get_memory(param as usize),
            ParameterMode::Relative => {
                let address = (self.relative_base + param) as usize;
                self.get_memory(address)
            }
        }
    }

    fn get_write_address(&self, param: i128, mode: ParameterMode) -> usize {
        match mode {
            ParameterMode::Memory => param as usize,
            ParameterMode::Relative => (self.relative_base + param) as usize,
            ParameterMode::Immediate => panic!("Cannot write to immediate mode parameter"),
        }
    }

    fn parse_instruction(&self, instruction: i128) -> (Opcode, [ParameterMode; 3]) {
        let opcode = Opcode::try_from(instruction % 100).unwrap();
        let modes = [
            ParameterMode::from((instruction / 100) % 10),
            ParameterMode::from((instruction / 1000) % 10),
            ParameterMode::from((instruction / 10000) % 10),
        ];
        (opcode, modes)
    }

    pub fn step(&mut self) -> Result<bool, String> {
        if self.halted {
            return Ok(false);
        }

        let instruction = self.get_memory(self.instruction_pointer);
        let (opcode, modes) = self.parse_instruction(instruction);

        match opcode {
            Opcode::Add => {
                let param1 = self.get_memory(self.instruction_pointer + 1);
                let param2 = self.get_memory(self.instruction_pointer + 2);
                let param3 = self.get_memory(self.instruction_pointer + 3);

                let val1 = self.get_parameter_value(param1, modes[0]);
                let val2 = self.get_parameter_value(param2, modes[1]);
                let addr = self.get_write_address(param3, modes[2]);

                self.set_memory(addr, val1 + val2);
                self.instruction_pointer += 4;
            }
            Opcode::Mul => {
                let param1 = self.get_memory(self.instruction_pointer + 1);
                let param2 = self.get_memory(self.instruction_pointer + 2);
                let param3 = self.get_memory(self.instruction_pointer + 3);

                let val1 = self.get_parameter_value(param1, modes[0]);
                let val2 = self.get_parameter_value(param2, modes[1]);
                let addr = self.get_write_address(param3, modes[2]);

                self.set_memory(addr, val1 * val2);
                self.instruction_pointer += 4;
            }
            Opcode::Input => {
                let input_value = if self.input_queue.is_empty() {
                    -1
                } else {
                    self.input_queue.remove(0)
                };
                let param1 = self.get_memory(self.instruction_pointer + 1);
                let addr = self.get_write_address(param1, modes[0]);

                self.set_memory(addr, input_value);
                self.instruction_pointer += 2;
            }
            Opcode::Output => {
                let param1 = self.get_memory(self.instruction_pointer + 1);
                let value = self.get_parameter_value(param1, modes[0]);

                self.output_queue.push(value);
                self.instruction_pointer += 2;
            }
            Opcode::JumpTrue => {
                let param1 = self.get_memory(self.instruction_pointer + 1);
                let param2 = self.get_memory(self.instruction_pointer + 2);

                let val1 = self.get_parameter_value(param1, modes[0]);
                let val2 = self.get_parameter_value(param2, modes[1]);

                if val1 != 0 {
                    self.instruction_pointer = val2 as usize;
                } else {
                    self.instruction_pointer += 3;
                }
            }
            Opcode::JumpFalse => {
                let param1 = self.get_memory(self.instruction_pointer + 1);
                let param2 = self.get_memory(self.instruction_pointer + 2);

                let val1 = self.get_parameter_value(param1, modes[0]);
                let val2 = self.get_parameter_value(param2, modes[1]);

                if val1 == 0 {
                    self.instruction_pointer = val2 as usize;
                } else {
                    self.instruction_pointer += 3;
                }
            }
            Opcode::Less => {
                let param1 = self.get_memory(self.instruction_pointer + 1);
                let param2 = self.get_memory(self.instruction_pointer + 2);
                let param3 = self.get_memory(self.instruction_pointer + 3);

                let val1 = self.get_parameter_value(param1, modes[0]);
                let val2 = self.get_parameter_value(param2, modes[1]);
                let addr = self.get_write_address(param3, modes[2]);

                self.set_memory(addr, if val1 < val2 { 1 } else { 0 });
                self.instruction_pointer += 4;
            }
            Opcode::Equal => {
                let param1 = self.get_memory(self.instruction_pointer + 1);
                let param2 = self.get_memory(self.instruction_pointer + 2);
                let param3 = self.get_memory(self.instruction_pointer + 3);

                let val1 = self.get_parameter_value(param1, modes[0]);
                let val2 = self.get_parameter_value(param2, modes[1]);
                let addr = self.get_write_address(param3, modes[2]);

                self.set_memory(addr, if val1 == val2 { 1 } else { 0 });
                self.instruction_pointer += 4;
            }
            Opcode::AdjustRelBase => {
                let param1 = self.get_memory(self.instruction_pointer + 1);
                let val1 = self.get_parameter_value(param1, modes[0]);

                self.relative_base += val1;
                self.instruction_pointer += 2;
            }
            Opcode::Halt => {
                self.halted = true;
                return Ok(false);
            }
        }

        Ok(true)
    }

    pub fn run_until_halt(&mut self) -> Result<(), String> {
        loop {
            if !self.step()? {
                break;
            }
        }
        Ok(())
    }

    pub fn run_until_output(&mut self) -> Result<Option<i128>, String> {
        let initial_output_count = self.output_queue.len();
        
        loop {
            if !self.step()? {
                break;
            }
            if self.output_queue.len() > initial_output_count {
                return Ok(self.output_queue.last().copied());
            }
        }
        Ok(None)
    }

    pub fn run_until_address(&mut self, target_address: usize, max_steps: Option<usize>) -> Result<bool, String> {
        let mut steps = 0;
        
        loop {
            if let Some(max) = max_steps {
                if steps >= max {
                    return Err("Exceeded maximum steps".to_string());
                }
            }
            
            if self.instruction_pointer == target_address {
                return Ok(true);
            }
            
            if !self.step()? {
                return Ok(false); // Halted before reaching target
            }
            
            steps += 1;
        }
    }
}

pub struct FunctionCaller {
    vm: IntcodeVm,
    program_size: usize,
}

impl FunctionCaller {
    pub fn new(program: Vec<i128>) -> Self {
        let program_size = program.len();
        let vm = IntcodeVm::new(program);
        
        Self {
            vm,
            program_size,
        }
    }

    pub fn get_memory(&self, address: usize) -> i128 {
        self.vm.get_memory(address)
    }

    pub fn set_memory(&mut self, address: usize, value: i128) {
        self.vm.set_memory(address, value);
    }

    pub fn push_input(&mut self, value: i128) {
        self.vm.push_input(value);
    }

    pub fn clear_input(&mut self) {
        self.vm.input_queue.clear();
    }

    pub fn set_input_string(&mut self, text: &str) {
        self.clear_input();
        for byte in text.bytes() {
            self.push_input(byte as i128);
        }
        self.push_input(10); // Add newline
    }

    pub fn call_function(&mut self, addr: usize, args: &[i128]) -> Result<CallResult, String> {
        let stack_base = self.program_size + 1000; // Well above program size
        let return_address = 999999; // Unique return address marker
        
        // Set up R register
        self.vm.set_relative_base(stack_base as i128);
        
        // Set return address at [R]
        let r_base = self.vm.get_relative_base() as usize;
        self.vm.set_memory(r_base, return_address as i128);
        
        // Set arguments at [R+1], [R+2], etc.
        for (i, &arg) in args.iter().enumerate() {
            self.vm.set_memory(r_base + 1 + i, arg);
        }
        
        // Jump to function
        self.vm.instruction_pointer = addr;
        
        // Clear previous outputs
        self.vm.clear_outputs();
        
        // Run until we return to the return address
        let result = self.vm.run_until_address(return_address, Some(1000000));
        
        match result {
            Ok(true) => {
                // Successfully returned, collect results
                let outputs = self.vm.get_outputs().to_vec();
                
                // Collect potential return values from positive R offsets
                let mut return_values = Vec::new();
                for i in 1..=10 { // Check first 10 potential return slots
                    let value = self.vm.get_memory(r_base + i);
                    return_values.push(value);
                }
                
                Ok(CallResult {
                    outputs,
                    return_values,
                    completed: true,
                })
            }
            Ok(false) => Ok(CallResult {
                outputs: self.vm.get_outputs().to_vec(),
                return_values: Vec::new(),
                completed: false,
            }),
            Err(e) => Err(e),
        }
    }
}

#[derive(Debug)]
pub struct CallResult {
    pub outputs: Vec<i128>,
    pub return_values: Vec<i128>,
    pub completed: bool,
}