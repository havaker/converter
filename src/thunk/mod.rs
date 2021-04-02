use goblin::{
    elf,
    elf64::sym::{STB_GLOBAL, STB_LOCAL, STT_FUNC, STV_DEFAULT},
};
use std::{cell::RefCell, rc::Rc};

use super::rel::*;

const CALL32FROM64_TEMPLATE: &[u8] = include_bytes!("../../assets/call32from64.o");
const JUMPTO64_TEMPLATE: &[u8] = include_bytes!("../../assets/jumpto64.o");
const CALL64_TEMPLATE: &[u8] = include_bytes!("../../assets/call64.o");
const JUMPTO32_TEMPLATE: &[u8] = include_bytes!("../../assets/jumpto32.o");

pub enum ThunkType {
    Call32From64(Rc<RefCell<Symbol>>),
    JumpTo64,
    Call64(Rc<RefCell<Symbol>>),
    JumpTo32,
}

#[derive(Debug, Clone)]
pub struct Thunk {
    text: Rc<RefCell<Section>>,
    text_relocs: RelocSection,
    text_symbol: Rc<RefCell<Symbol>>,

    rodata: Rc<RefCell<Section>>,
    rodata_relocs: RelocSection,
    rodata_symbol: Rc<RefCell<Symbol>>,

    generated_fun_symbols: Vec<Rc<RefCell<Symbol>>>,
}

impl Thunk {
    pub fn generated_fun(&self) -> Option<Rc<RefCell<Symbol>>> {
        self.generated_fun_symbols.first().cloned()
    }

    pub fn new(thunk_type: ThunkType) -> Self {
        let should_generated_func_symbol_be_global = if let ThunkType::Call64(_) = thunk_type {
            false
        } else {
            true
        };

        let (buffer, fun_symbol) = match thunk_type {
            ThunkType::Call32From64(sym) => (CALL32FROM64_TEMPLATE, Some(sym)),
            ThunkType::JumpTo64 => (JUMPTO64_TEMPLATE, None),
            ThunkType::Call64(sym) => (CALL64_TEMPLATE, Some(sym)),
            ThunkType::JumpTo32 => (JUMPTO32_TEMPLATE, None),
        };

        let elf = Elf::new(&buffer.to_vec());

        let text = elf.section_by_name(".text").unwrap();
        let rodata = elf.section_by_name(".rodata").unwrap();

        let text_relocs = elf.reloc_section_by_name(".text").unwrap();
        let rodata_relocs = elf.reloc_section_by_name(".rodata").unwrap();

        // change name
        // TODO in/out
        text.borrow_mut().name = ".text.thunk".into();
        rodata.borrow_mut().name = ".rodata.thunk".into();

        let generated_fun_symbols = if let Some(fun_symbol) = fun_symbol.clone() {
            // TODO global or local
            let generated_fun_symbol = Self::generate_fun_symbol(
                fun_symbol,
                text.clone(),
                should_generated_func_symbol_be_global,
            );

            vec![generated_fun_symbol]
        } else {
            vec![]
        };

        let mut thunk = Self {
            text,
            rodata,
            text_relocs,
            rodata_relocs,
            text_symbol: elf.section_symbol_by_name(".text.thunk").unwrap(),
            rodata_symbol: elf.section_symbol_by_name(".rodata.thunk").unwrap(),
            generated_fun_symbols,
        };

        if should_generated_func_symbol_be_global {
            if let Some(sym) = fun_symbol {
                thunk.replace_fun_symbol(sym);
            }
        } else {
            if let Some(_) = thunk.generated_fun_symbols.first().cloned() {
                //let import: Symbol = fun_symbol.as_ref().unwrap().borrow().clone();
                //let new_sym = Rc::new(RefCell::new(import));
                thunk.replace_fun_symbol(fun_symbol.unwrap());
                //dbg!(&thunk);
            }
        }

        thunk
    }

    fn generate_fun_symbol(
        fun_symbol: Rc<RefCell<Symbol>>,
        code_section: Rc<RefCell<Section>>,
        is_global: bool,
    ) -> Rc<RefCell<Symbol>> {
        let fun_name = fun_symbol.borrow().name.clone().unwrap();
        let fun_size = code_section.borrow().content.len();

        let binding = if is_global { STB_GLOBAL } else { STB_LOCAL };

        Rc::new(RefCell::new(Symbol {
            name: Some(fun_name.clone()),
            section: Some(code_section),
            sym: elf::Sym {
                st_name: 0,
                st_info: create_st_info(binding, STT_FUNC),
                st_other: STV_DEFAULT,
                st_shndx: 0,
                st_value: 0,
                st_size: fun_size as u64,
            },

            index: None,
        }))
    }

    pub fn merge_sections(&mut self, mut other: Thunk) {
        let self_text_len = self.text.borrow().content.len();
        let self_rodata_len = self.rodata.borrow().content.len();

        self.text
            .borrow_mut()
            .extend(other.text.borrow().content.as_slice());
        self.rodata
            .borrow_mut()
            .extend(other.rodata.borrow().content.as_slice());

        other.text = self.text.clone();
        other.rodata = self.rodata.clone();

        // add symbols generated by other thunk to self, shift them by text.len()
        let self_text = self.text.clone(); // borrow checker
        let other_generated_fun_symbols =
            other.generated_fun_symbols.into_iter().map(|symbol_rc| {
                {
                    let symbol: &mut Symbol = &mut symbol_rc.borrow_mut();
                    symbol.section = Some(self_text.clone());
                    symbol.sym.st_value += self_text_len as u64;
                }

                symbol_rc
            });
        self.generated_fun_symbols
            .extend(other_generated_fun_symbols);

        Self::shift_relocs(
            &mut other.text_relocs,
            self.rodata_symbol.clone(),
            self_rodata_len,
            self_text_len,
        );
        Self::shift_relocs(
            &mut other.rodata_relocs,
            self.text_symbol.clone(),
            self_text_len,
            self_rodata_len,
        );

        self.text_relocs.relocs.extend(other.text_relocs.relocs);
        self.rodata_relocs.relocs.extend(other.rodata_relocs.relocs);
    }

    pub fn append_text(&mut self, text: &[u8]) {
        self.text.borrow_mut().extend(text);
        for symbol in &self.generated_fun_symbols {
            symbol.borrow_mut().sym.st_size += text.len() as u64;
        }
    }

    pub fn prepend_text(&mut self, text: &[u8]) {
        self.text.borrow_mut().extend_front(text);

        //self.generated_fun_symbol.borrow_mut().sym.st_value += text.len() as u64;

        for reloc in &mut self.text_relocs.relocs {
            reloc.reloc.r_offset += text.len() as u64;
        }
        for reloc in &mut self.rodata_relocs.relocs {
            if let Some(addend) = &mut reloc.reloc.r_addend {
                *addend += text.len() as i64;
            }
        }
    }

    fn shift_relocs(
        reloc_section: &mut RelocSection,
        source_section_symbol: Rc<RefCell<Symbol>>,
        source_section_shift: usize,
        target_section_shift: usize,
    ) {
        let section_name = source_section_symbol.borrow().section_name().unwrap();

        for reloc in reloc_section.relocs.iter_mut() {
            let symbol_section = reloc.symbol.borrow().section_name();

            match symbol_section.as_ref() {
                Some(name) if name == &section_name => {
                    reloc.symbol = source_section_symbol.clone();
                    if let Some(addend) = &mut reloc.reloc.r_addend {
                        *addend += source_section_shift as i64;
                    }
                }
                Some(_) => (),
                _ => unreachable!(),
            }

            reloc.reloc.r_offset += target_section_shift as u64;
        }
    }

    fn replace_fun_symbol(&mut self, fun_symbol: Rc<RefCell<Symbol>>) {
        for reloc in &mut self.text_relocs.relocs {
            if reloc.symbol.borrow().name.as_ref().map(|n| n.as_str()) == Some("fun") {
                reloc.symbol = fun_symbol.clone();
            }
        }
    }
}

pub fn merge_thunks(mut thunks: impl Iterator<Item = Thunk>) -> Elf {
    let mut e: Elf = Default::default();

    let mut first = match thunks.next() {
        Some(thunk) => thunk,
        None => return e,
    };

    for thunk in thunks {
        first.merge_sections(thunk);
    }

    e.sections.push(first.text);
    e.sections.push(first.rodata);
    e.reloc_sections.push(first.text_relocs);
    e.reloc_sections.push(first.rodata_relocs);
    e.symtab.symbols.push(first.text_symbol);
    e.symtab.symbols.push(first.rodata_symbol);
    e.symtab.extend(first.generated_fun_symbols);

    e
}
