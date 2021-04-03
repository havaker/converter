use goblin::{
    elf,
    elf64::{
        section_header::SHN_UNDEF,
        sym::{STB_GLOBAL, STB_LOCAL, STB_WEAK, STT_FUNC},
    },
};
use keystone::{Arch, Keystone, Mode, OptionType, OptionValue};
use std::{cell::RefCell, collections::HashMap, rc::Rc};

use super::func::Function;
use super::thunk::*;
use crate::rel::{create_st_info, Elf, Symbol};

pub struct Generator {
    engine: Keystone,
    functions: HashMap<String, Function>,
}

impl Generator {
    pub fn new(functions: HashMap<String, Function>) -> Self {
        let engine =
            Keystone::new(Arch::X86, Mode::MODE_64).expect("could not initialize Keystone engine");
        engine
            .option(OptionType::SYNTAX, OptionValue::SYNTAX_GAS)
            .expect("could not set option to GNU assembler syntax");

        Generator { engine, functions }
    }

    fn signature<'a>(&'a self, func_symbol: &Symbol) -> Option<&'a Function> {
        self.functions.get(
            func_symbol
                .name
                .as_ref()
                .expect("func symbol should have a name"),
        )
    }

    pub fn generate_thunks(&self, rel: &mut Elf) {
        let has_name = |symbol: &&Rc<RefCell<Symbol>>| {
            let name = &symbol.borrow().name;
            name.is_some()
        };

        let is_global_func = |symbol: &&Rc<RefCell<Symbol>>| {
            let sym: &elf::Sym = &symbol.borrow().sym;
            let is_function = sym.st_type() == STT_FUNC;
            let is_global = sym.st_bind() == STB_GLOBAL || sym.st_bind() == STB_WEAK;

            is_function && is_global
        };

        let is_import_func = |symbol: &&Rc<RefCell<Symbol>>| {
            let sym: &elf::Sym = &symbol.borrow().sym;
            let is_undefined = sym.st_shndx == SHN_UNDEF as usize;

            is_undefined
        };

        let global_func_symbols = rel
            .symtab
            .symbols
            .iter()
            .filter(has_name)
            .filter(is_global_func)
            .cloned()
            .collect::<Vec<_>>() // issues with borrow checker
            .into_iter();

        let import_func_symbols = rel
            .symtab
            .symbols
            .iter()
            .filter(has_name)
            .filter(is_import_func)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter();

        self.generate_thunkins(global_func_symbols, rel);
        self.generate_thunkouts(import_func_symbols, rel);
    }

    fn generate_thunkins(&self, funcs: impl Iterator<Item = Rc<RefCell<Symbol>>>, rel: &mut Elf) {
        let mut thunks = Vec::new();
        for func in funcs {
            let thunk = match self.generate_thunkin(func.clone()) {
                Some(thunk) => thunk,
                None => {
                    eprintln!("could not generate thunkin for symbol: {:?}", func);
                    continue;
                }
            };

            thunks.push(thunk);
        }

        let mut merged_thunks = merge_thunks(thunks.into_iter());
        merged_thunks.add_suffix_to_section_names("in");
        rel.merge(merged_thunks);
    }

    fn generate_thunkouts(&self, funcs: impl Iterator<Item = Rc<RefCell<Symbol>>>, rel: &mut Elf) {
        let mut thunks = Vec::new();
        for func in funcs {
            let thunk = match self.generate_thunkout(rel, func.clone()) {
                Some(thunk) => thunk,
                None => {
                    eprintln!("could not generate thunkout for symbol: {:?}", func);
                    continue;
                }
            };

            thunks.push(thunk);
        }

        let mut merged_thunks = merge_thunks(thunks.into_iter());
        merged_thunks.add_suffix_to_section_names("out");
        rel.merge(merged_thunks);
    }

    fn generate_thunkin(&self, func: Rc<RefCell<Symbol>>) -> Option<Thunk> {
        let signature = match self.signature(&func.borrow()) {
            Some(s) => s,
            None => return None,
        };

        let params_asm = signature.parameters_to_32bit_convention();
        let return_value_asm = signature.return_value_to_32bit_convention();

        let params = self
            .engine
            .asm(params_asm, 0)
            .expect("could not assemble")
            .bytes;
        let return_value = self
            .engine
            .asm(return_value_asm, 0)
            .expect("could not assemble")
            .bytes;

        func.borrow_mut().sym.st_info = create_st_info(STB_LOCAL, STT_FUNC);

        let mut thunk = Thunk::new(ThunkType::Call32From64(func.clone()));
        thunk.prepend_text(params.as_slice());
        thunk.append_text(return_value.as_slice());

        Some(thunk)
    }

    fn generate_thunkout(&self, elf: &mut Elf, func: Rc<RefCell<Symbol>>) -> Option<Thunk> {
        let jumpto64 = Thunk::new(ThunkType::JumpTo64);
        let mut call64 = Thunk::new(ThunkType::Call64(func.clone()));
        let jumpto32 = Thunk::new(ThunkType::JumpTo32);

        let signature = match self.signature(&func.borrow()) {
            Some(s) => s,
            None => return None,
        };

        let params_asm = signature.parameters_to_64bit_convention();
        let return_value_asm = signature.return_value_to_64bit_convention();

        let params = self
            .engine
            .asm(params_asm, 0)
            .expect("could not assemble")
            .bytes;
        let return_value = self
            .engine
            .asm(return_value_asm, 0)
            .expect("could not assemble")
            .bytes;

        call64.prepend_text(&params);
        call64.append_text(&return_value);

        let generated_fun = call64.generated_fun().unwrap();

        let mut result = jumpto64;
        result.merge_sections(call64);
        result.merge_sections(jumpto32);

        generated_fun.borrow_mut().sym.st_value = 0;

        for reloc_section in elf.reloc_sections.iter_mut() {
            for reloc in &mut reloc_section.relocs {
                if &*reloc.symbol as *const RefCell<Symbol> == &*func as *const RefCell<Symbol> {
                    reloc.symbol = generated_fun.clone();
                }
            }
        }

        Some(result)
    }
}
