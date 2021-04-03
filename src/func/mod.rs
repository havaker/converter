use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

#[derive(Debug, Clone, PartialEq)]
pub enum ValueType {
    Int,
    UInt,
    Long,
    ULong,
    LongLong,
    ULongLong,
    Ptr,
}

#[derive(Debug, Clone)]
pub struct Function {
    name: String,
    return_type: Option<ValueType>,
    parameters: Vec<ValueType>,
}

impl Function {
    pub fn load(path: impl AsRef<Path>) -> io::Result<HashMap<String, Function>> {
        let lines = read_lines(path)?;

        let mut functions = HashMap::new();
        for line in lines {
            let line = &line?;
            if line.chars().all(char::is_whitespace) {
                continue;
            }

            let function = Self::parse(line);
            functions.insert(function.name.clone(), function);
        }

        Ok(functions)
    }

    pub fn parameters_to_32bit_convention(&self) -> String {
        let mut instructions = vec![];
        let mut offset = 0;
        for (index, param) in self.parameters.iter().enumerate() {
            let size = param.size(false);
            let is_big = size == 8;
            let register_name = Self::get_register_name(index, is_big);
            let mov_suffix = if is_big { "q" } else { "l" };

            // saves argument on stack
            let mov = format!(
                "mov{} %{}, {:#04x}(%rsp); ",
                mov_suffix, register_name, offset
            );
            instructions.push(mov);

            offset += size;
        }

        // grows stack to fit arguments
        let grow_stack = format!("subq ${:#04x}, %rsp; ", self.stack_size());
        instructions.push(grow_stack);

        // saving registers that get destroyed during switch to 64-bit mode
        const SAVE_REGISTERS: &'static str = "\
            pushq %rbx; \
            pushq %rbp; \
            pushq %r12; \
            pushq %r13; \
            pushq %r14; \
            pushq %r15; ";
        instructions.push(SAVE_REGISTERS.into());

        instructions.reverse();
        let merged: String = instructions.iter().flat_map(|s| s.chars()).collect();

        merged
    }

    pub fn return_value_to_32bit_convention(&self) -> String {
        let convert_ret = if let Some(8) = self.return_type.as_ref().map(|t| t.size(false)) {
            "mov %eax, %eax; \
             shlq $0x20, %rdx; \
             orq %rdx, %rax; "
        } else {
            ""
        };

        let ungrow_stack = format!("addq ${:#04x}, %rsp; ", self.stack_size());

        const RESTORE_REGISTERS: &'static str = "\
            popq %r15; \
            popq %r14; \
            popq %r13; \
            popq %r12; \
            popq %rbp; \
            popq %rbx; ";

        format!(
            "{}{}{} retq; ",
            convert_ret, ungrow_stack, RESTORE_REGISTERS
        )
    }

    pub fn parse(line: &str) -> Function {
        let mut it = line.split(" ");
        let name = it.next().expect("function should have a name").to_string();
        let return_type = ValueType::parse(it.next().expect("function should have a return type"));

        let parameters = it
            .map(|word| ValueType::parse(word).expect("void is not a valid parameter type"))
            .collect();

        Function {
            name,
            return_type,
            parameters,
        }
    }

    fn get_register_name(index: usize, is_64: bool) -> &'static str {
        let r64 = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
        let r32 = ["edi", "esi", "edx", "ecx", "r8d", "r9d"];
        if is_64 {
            r64[index]
        } else {
            r32[index]
        }
    }

    fn stack_size(&self) -> usize {
        let mut stack_size: usize = self.parameters.iter().map(|p| p.size(false)).sum();
        while stack_size % 16 != 8 {
            stack_size += 4;
        }

        stack_size
    }
}

impl ValueType {
    fn parse(word: &str) -> Option<ValueType> {
        use ValueType::*;
        match word {
            "void" => None,
            "int" => Some(Int),
            "uint" => Some(UInt),
            "long" => Some(Long),
            "ulong" => Some(ULong),
            "longlong" => Some(LongLong),
            "ulonglong" => Some(ULongLong),
            "ptr" => Some(Ptr),
            _ => panic!("invalid type"),
        }
    }

    fn size(&self, is_64: bool) -> usize {
        use ValueType::*;
        match &self {
            Int | UInt => 4,
            Ptr | Long | ULong => {
                if is_64 {
                    8
                } else {
                    4
                }
            }
            LongLong | ULongLong => 8,
        }
    }
}

fn read_lines(filename: impl AsRef<Path>) -> io::Result<io::Lines<io::BufReader<File>>> {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let signature = "fputc int int ptr";
        let function = Function::parse(signature);

        assert_eq!(function.name, "fputc");
        assert_eq!(function.return_type, Some(ValueType::Int));
        assert_eq!(function.parameters, vec![ValueType::Int, ValueType::Ptr]);
    }

    #[test]
    fn test_void() {
        let signature = "fputc void int ptr";
        let function = Function::parse(signature);

        assert_eq!(function.return_type, None);
    }

    #[test]
    fn test_instruction_generation() {
        let signature = "fun longlong ptr int longlong";
        let function = Function::parse(signature);

        let expected_params32 = "\
            pushq %rbx; \
            pushq %rbp; \
            pushq %r12; \
            pushq %r13; \
            pushq %r14; \
            pushq %r15; \
            subq $0x18, %rsp; \
            movq %rdx, 0x08(%rsp); \
            movl %esi, 0x04(%rsp); \
            movl %edi, 0x00(%rsp); ";

        assert_eq!(expected_params32, function.parameters_to_32bit_convention());
    }
}
