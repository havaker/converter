use goblin::{
    elf,
    elf64::sym::{STB_GLOBAL, STB_LOCAL, STB_WEAK, STT_FUNC},
    error,
};
use keystone::*;
use std::{cell::RefCell, collections::HashMap, env, ffi::OsString, fs, rc::Rc};

mod func;
mod rel;
mod thunk;

use func::*;
use rel::*;
use thunk::*;

// TODO R_X86_64_32 or R_X86_64_32S

fn main() -> error::Result<()> {
    let args: Vec<OsString> = env::args_os().collect();
    if args.len() != 4 {
        panic!("invalid argument count");
    }

    let input_path = &args[1];
    let function_list_path = &args[2];
    let output_path = &args[3];

    dbg!(&args);

    let functions = Function::load(function_list_path)?;
    let buffer = fs::read(input_path)?;

    let converted = convert(&buffer, functions);

    fs::write(output_path, &converted)?;

    Ok(())
}

fn convert(buffer: &Vec<u8>, functions: HashMap<String, Function>) -> Vec<u8> {
    let mut e = rel::Elf::new(buffer);

    let section_names = &e
        .sections
        .iter()
        .map(|s| s.borrow().name.clone())
        .collect::<Vec<_>>();

    dbg!(&section_names);

    for section in &mut e.reloc_sections {
        section.to_rela();
    }

    let is_global_func = |symbol: &&Rc<RefCell<Symbol>>| {
        let sym: &elf::Sym = &symbol.borrow().sym;
        let is_function = sym.st_type() == STT_FUNC;
        let is_global = sym.st_bind() == STB_GLOBAL || sym.st_bind() == STB_WEAK;

        is_function && is_global
    };

    let is_import_func = |symbol: &&Rc<RefCell<Symbol>>| {
        let sym: &elf::Sym = &symbol.borrow().sym;
        let is_import = sym.is_import();
        let is_known = symbol.borrow().name == Some("to64".to_string());
        let is_known2 = symbol.borrow().name == Some("to64_2".to_string());

        (is_known || is_known2) && is_import
    };

    let mut global_func_symbols = e
        .symtab
        .symbols
        .iter()
        .filter(is_global_func)
        .cloned()
        .collect::<Vec<_>>();

    let import_func_symbols = e
        .symtab
        .symbols
        .iter()
        .filter(is_import_func)
        .cloned()
        .collect::<Vec<_>>();

    dbg!(&import_func_symbols);

    let mut thunkins = Vec::new();

    let engine =
        Keystone::new(Arch::X86, Mode::MODE_64).expect("Could not initialize Keystone engine");
    engine
        .option(OptionType::SYNTAX, OptionValue::SYNTAX_GAS)
        .expect("Could not set option to gas syntax");

    for func_symbol in &mut global_func_symbols {
        let name = func_symbol
            .borrow()
            .name
            .clone()
            .expect("global func must have a name");

        let func_signature = functions.get(&name).expect("unknown function");

        let params_asm = func_signature.parameters_to_32bit_convention();
        let return_value_asm = func_signature.return_value_to_32bit_convention();

        let params = engine.asm(params_asm, 0).expect("could not assemble").bytes;
        let return_value = engine
            .asm(return_value_asm, 0)
            .expect("could not assemble")
            .bytes;

        let mut thunk = Thunk::new(ThunkType::Call32From64(func_symbol.clone()));
        thunk.prepend_text(params.as_slice());
        thunk.append_text(return_value.as_slice());
        thunkins.push(thunk);

        let mut sym = func_symbol.borrow_mut();
        sym.sym.st_info = create_st_info(STB_LOCAL, STT_FUNC);
    }

    let mut thunkin = merge_thunks(thunkins.into_iter());
    thunkin.add_suffix_to_section_names("in");
    e.merge(thunkin);

    let mut thunkouts = Vec::new();
    for func in &import_func_symbols {
        let thunk = generate_thunkout(&mut e, func.clone());
        thunkouts.push(thunk);
    }

    let mut thunkout = merge_thunks(thunkouts.into_iter());
    thunkout.add_suffix_to_section_names("out");
    e.merge(thunkout);

    e.serialize()
}

fn generate_thunkout(e: &mut Elf, func: Rc<RefCell<Symbol>>) -> Thunk {
    let mut jumpto64 = Thunk::new(ThunkType::JumpTo64);
    let mut call64 = Thunk::new(ThunkType::Call64(func.clone()));
    let jumpto32 = Thunk::new(ThunkType::JumpTo32);

    let engine =
        Keystone::new(Arch::X86, Mode::MODE_64).expect("Could not initialize Keystone engine");
    engine
        .option(OptionType::SYNTAX, OptionValue::SYNTAX_GAS)
        .expect("Could not set option to gas syntax");
    let prepend = engine
        .asm(
            "movl 0x10(%rsp), %edi; movslq 0x14(%rsp), %rsi; movq 0x18(%rsp), %rdx;".to_string(),
            0,
        )
        .expect("Could not assemble")
        .bytes;

    let append = engine
        .asm("movq %rax, %rdx; shrq $32, %rdx;".to_string(), 0)
        .expect("Could not assemble")
        .bytes;

    call64.prepend_text(&prepend);
    call64.append_text(&append);

    let generated_fun = call64.generated_fun().unwrap();

    jumpto64.merge_sections(call64);
    jumpto64.merge_sections(jumpto32);
    generated_fun.borrow_mut().sym.st_value = 0;

    for reloc_section in e.reloc_sections.iter_mut() {
        for reloc in &mut reloc_section.relocs {
            if &*reloc.symbol as *const RefCell<Symbol> == &*func as *const RefCell<Symbol> {
                reloc.symbol = generated_fun.clone();
            }
        }
    }

    jumpto64
}
