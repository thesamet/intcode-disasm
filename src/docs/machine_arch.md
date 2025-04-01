# Background

In this project, we are building a decompiler for programs written in "Intcode assembly language". The project contains a CLI that can be used to compile, decompile and decompile to assembly. However, the most interesting part is to
translate the decompiled assembly into higher-level language and include inferred type information.

# Machine Instruction Architecture

An Intcode program is a list of integers separated by commas (like 1,0,0,3,99).
The computer starts executing from the first number. The offsets are zero-based.
The program is a sequence of opcodes following by zero or more arguments.

The following opcodes are defined:
- `1`: Addition
- `2`: Multiplication
- `3`: Input
- `4`: Output
- `5`: Jump if true
- `6`: Jump if false
- `7`: Less than
- `8`: Equals
- `9`: Adjust relative base
- `99`: Halt

Let's dive into the details of each opcode:

## 1 Addition
Opcode 1 adds together numbers read from two positions and stores the result in a third position. The three integers immediately after the opcode tell you these three positions - the first two indicate the positions from which you should read the input values, and the third indicates the position at which the output should be stored.

For example, if your Intcode computer encounters 1,10,20,30, it should read the values at positions 10 and 20, add those values, and then overwrite the value at position 30 with their sum.


## 2 Multiplication
Opcode 2 multiplies together numbers read from two positions and stores the result in a third position. The three integers immediately after the opcode tell you these three positions - the first two indicate the positions from which you should read the input values, and the third indicates the position at which the output should be stored.

## 3 Input
Opcode 3 reads a single integer from input and saves it to the position given by its only parameter. For example, the instruction 3,50 would take an input value and store it at address 50. In some context we assume the input is an ASCII character.

## 4 Output
Opcode 4 outputs the value of its only parameter. For example, the instruction 4,50 would output the value at address 50. In some context we assume the output is an ASCII character.

## 5 Jump if true
Opcode 5 has two parameters. It jumps to the address given by the second parameter if the first parameter is non-zero. Otherwise, it does nothing.

## 6 Jump if false
Opcode 6 has two parameters. It jumps to the address given by the second parameter if the first parameter is zero. Otherwise, it does nothing.

## 7 Less than
Opcode 7 has two parameters. stores 1 in the position given by the third parameter if the first parameter is less than the second parameter. Otherwise, it stores 0.

## 8 Equals
Opcode 8 has three parameters. It stores 1 in the position given by the third parameter if the first parameter is equal to the second parameter. Otherwise, it stores 0.

## 9 Adjust relative base
Opcode 9 adjusts the relative base by the value of its only parameter. The relative, denoted by `R` base increases (or decreases, if the value is negative) by the value of the parameter. The relative base is a global register that is used in loading or storing value in memory addresses relative to the relative base (R).

## 99 Halt
Opcode 99 halts the program. It accepts no parameters

# Parameter modes
Parameter modes are used to specify how the parameters of an instruction are interpreted. There are three modes (0, 1 and 2):

## 0: Memory mode
The parameter is interpreted as an address in memory. Reads which read the value in memory at the given address. Writes will overwrite the value in memory at the given address. This is denoted in assembly as `[address]` for example `[10]`.


## 1: Value mode
The parameter is interpreted as a value. The value is written directly in the code as constant.

## 2: Relative mode
The parameter is interpreted as a memory location offset relative to R (the relative base). For example, if the mode is 2, and the relative base is 100, then the parameter is interpreted as an address in memory at the address `100 + parameter` and will be denoted in code as `[R+parameter]`, for example `R+100`. The parameter cas be negative offset. For example if it is -50 it will be denoted as `[R-50]`.

The mode of each parameter is specified by a digit in the opcode, starting from the third digit from the right (the hundreds) and advances to the left. That is, the mode of the second parameter is the fourth digit from the right (thousands). The mode of the third parameter is in the fifth digit. The instruct code is in the first two digits. Here are a few examples:


```
1202,6,247,127
```

The first number is 1202. Its first two digits are 2, indicating this is a multiplication. The hundres digit from the right of 1202 is 2, which means the first parameter is in memory at the address `R+6`. The second parameter is at mode 1 (the thousands digit of 1202). Therefore it is the constant `247`. The third parameter is in memory mode at address 127 (since the 5 digit of 1202 is 0, we view it as 01202). This instruction will read the number at memory location `R+6` and multiply it with 247. Then, it will store the result at memory address `127`. In the assembly language it is denoted as `[127] = [R+6] * 247`.

# Program flow
After an instruction is read, the machine will read the following instruction in the integer list, unless it is a conditional jump instruction. In that case, the machine will jump to the address specified by the second parameter based on the condition given in first parameter. If the condition is not met, the machine will continue to read the next instruction.

# The assembly language

The assembly language denotes memory address like `[129]`, relative memory addresses `[R+129]`, and immediate values `129`. The addition and multiplication
operations are denoted as `[127] = [R+6] + 247` and `[127] = [R+6] * 247`, respectively.

Adjustments of `R` (instruction opcode 9) are written as `R += 123` or `R -= 123`. The argument is always a fixed number (mode 1).

## Conditional jumps

If-ture jumps are written as follows:
```
if [R+123] goto [R+124]
```

If-false jumps are written as follows:
```
if ![R+123] goto [R+124]
```

## Syntax Sugar
The language offers the following syntax sugar for common constructs that are not available in the assembly:

### Unconditional jumps (goto)
`goto x` jumps to the address `x`. Since there is no opcode for unconditional jumps, this is implemented using conditional jump "Jump if true", where the condition value (first argument) is 1. This ensures that the if-test is always true, effectively making it an unconditional jump. It is possible to goto immediate address, to addresses stored in a memory location, or to addresses in relative locations:

`goto 123`: jumps to the instruction at address 123.
`goto [R+123]`: reads the value stored at memory address `R+123`, and jumps to that value.
`goto [123]`: jumps to the address that is stored at memory at `[123]`.

For example, if the memory address 123 contains the value 50, the last instruction will jump to address 50 and execution will continue from there.

### Assignment `x = y`

The machine does not have direct assignment (copying the value from one location to another). This instruction is interpreted as addition of zero. For example:
`[R-3] = [127]` is translated to `[R-3] = 0 + [127]` which effectively copies the value from `[127]` to `[R-3]`.

### Labels
To make it easy to write goto, and if statements our parser has the notion of labels. Labels are defined on their own line in the form `name`. Then the labels can be referenced anywhere as `@name`. For example:

```
if [R-1] goto @after
[R-2] = 2 * [R-3]
[R-2] = 5 + [R-3]
goto @after:
@b1:
[R-2] = 4 + [R-3]
@after:
```

This creates an if-else structure. If [R-1] is non-zero we go the `b1` branch. If it is zero, the code continues to the statements below and the jumps to the address at `@after` where both branches join.

Similarly, here is how a while loop is achieve:

```
@start:
if [R-1] goto @end
  [R-1] = [R-1] - 1
  output(65)
  ; do things
goto @start
@end:
```

This will iterate as long as `[R-1] != 0`, and in each iteration `[R-1]` is decremented by 1 and the program outputs the character 'A'.

## Markers
To make it easy to test and debug the decompiler, we use markers to indicate the position of each argument:

```
[3] = 'b [4] + 'c [R-5]
goto 'd [R-3]
```

Markers are single letter followed by a single-quote. This is a non-standard
extention of the intcode specification made in this project. The value of the markers, similarly to mode are stored in the opcode starting at the sixth decimal digit. Each marker is represented as 8-bit ascii. If a parameter has no marker, the value 0 is used. For example, let's compute the opcode of the following instruction in multiple steps:

```
[3] = 'b [4] + 'c [R-5]
```

Start with 1 as  opcode for addition.
Add 02000 (decimal) since the first parameter is memory mode (0), the second parameter (`[R-5]`) is in relative mode (2), and the third paremter ('[3]') is in memory mode 0.

Finally add `2544200000 = 100000*(ord('c') << 8 + ord('b'))`
The result is `2544202001`

# Indirect memory access
Since the machine does not support reading or writing to a memory addresses stored in another memory location (similar to derefencing a pointer), programs use a clever trick: they modify the parameters of the read or write instruction in runtime! Let's work out an example.

Assume that at `[R-2]` we store an address of another memory location and that we want to read the value stored in that memory address into `[R+1]`. Assume
that the following code is starting from location 1000 in memory:

```
[1005] = [R-2]
[R+1] = [0] + 0
```
The first line copies the value of `[R-2]` into `[1005]`. The second instruction is located at address 1004, because assignment instructions are 4 bytes (because they are additions). That means that address 1005 is the address of the first parameter of second instruction. The first parameter is is memory mode. After the first instruction is executed, the first parameter of the second assignment becomes the value stored at `[R-2]`. When the second instruction is executed, the value stored at `[R-2]` is read into `[R+1]`. This is how indirect memory addressing works.

The parser allows for the use of indirect memory addressing using the following syntax:

```
ptr = 375
[R+1] = *ptr
```

The ptr object references the address of the instruction that derefences it. So `ptr=375` writes the value 375 into the memory address where the first argument of the instruction in the second line is located.

# Decompilation
This part summarizes patterns that emitted by the compiler we are trying to decompile.

Programs are typically thousands of numbers. They start by adjusting the R value to a positive value well above the address of the last instruction.
R is going as a stack pointer.

## Function calls are implemented as follows:
Step 1: set parameters at positive offsets relative to `R`:
Step 2: set the return address at `[R]`
Step 3: jump to the function address, maybe direct address or indirect address (`[R-2]`).
Step 4: the function executes and returns to the given address `R` when it complets.
Step 5: optionally, the caller reads the returned values from some positive `R` values.

For example:
```
[R+1] = 157        ; first argument is 157
[R+2] = [57] < 700 ; second argument is 1 if the value at [57]<700 otherwise 0
[R] = @return_address
goto @func_address

return_address:
; code continues after the function call and can inspect the return values
; at positive R values.
output([R+1])  ; prints the first returned value.
```

## Functions are implemented as follows:

Step 1: adjust R to a positive value to account for arguments and stack space for local variables.
Step 2: instruction code access arguments and local values at negative values relative to R.
Step 3: adjust R back to the original value by subtracting the number added in Step 1.
Step 4: Now we have the return value at [R], so `goto [R]` returns control to the caller.

The following function has 2 parameters, and increments the stack by 5 to leave space for 3 local variables.

```
@func_address:
R += 5
; multiply the second argument by the first argument and store the result in a local variable [R-2].
[R-2] = [R-4] * [R-3]
R -= 5
goto [R]
```

## Example: passing a function as a parameter to another function.

```
[R+1] = @other_func
[R+2] = 157
[R+3] = [57] < 700
[R] = @return_address
goto @func_address

return_address:
; code continues after the function call and can inspect the return values
; at positive R values.
output([R+1])  ; prints the first returned value.

func_address:
R += 5
[R+1] = 9
[R+2] = 15
[R] = @next
goto [R-4]  ; call the function provided as first argument.
next:
[R-4] = 5 + [R+1]  ; return 5 plus the return value of the provided function.
goto [R]
```

# Implementation details of low_ir

Phi instruction is used in SSA representation to represent the value of a variable at a given point in the program. It is used to represent the value of a variable that is defined by multiple paths in the program. Phi instructions are used to ensure that the value of a variable is consistent across all paths in the program.

The `Data` instruction is used to represent data values in the program. It is used to represent locations in the program that are constants or variables.

## Instruction simplification
The code has automatic simplification logic that converts certain patterns to more readable forms:

- Addition with 0 becomes assignment
- Multiplication by 1 becomes assignment
- Conditional jumps with constant conditions become unconditional jumps
