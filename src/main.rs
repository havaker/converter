use goblin::error;
use std::{collections::HashMap, env, ffi::OsString, fs};

mod gen;
mod rel;

use gen::*;

// TODO R_X86_64_32 or R_X86_64_32S

fn main() -> error::Result<()> {
    let args: Vec<OsString> = env::args_os().collect();
    if args.len() != 4 {
        panic!("invalid argument count");
    }

    let input_path = &args[1];
    let function_list_path = &args[2];
    let output_path = &args[3];

    let functions = Function::load(function_list_path)?;

    let elf_bytes = fs::read(input_path)?;
    let converted = convert(&elf_bytes, functions);
    fs::write(output_path, &converted)?;

    Ok(())
}

fn convert(buffer: &Vec<u8>, functions: HashMap<String, Function>) -> Vec<u8> {
    let mut e = rel::Elf::new(buffer);

    for section in &mut e.reloc_sections {
        section.to_rela();
    }

    let generator = Generator::new(functions);
    generator.generate_thunks(&mut e);

    e.serialize()
}
