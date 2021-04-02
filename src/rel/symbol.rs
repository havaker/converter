use goblin::elf;
use std::{cell::RefCell, rc::Rc};

use super::Section;
use super::Strtab;

#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: Option<String>,
    pub section: Option<Rc<RefCell<Section>>>,
    pub sym: elf::Sym,

    // computed during serialization process
    pub index: Option<usize>,
}

impl Symbol {
    pub fn get_sym_with_updated_indexes(&self, strtab: &Strtab) -> elf::Sym {
        let mut sym_copy = self.sym.clone();
        if let Some(section) = &self.section {
            sym_copy.st_shndx = section.borrow().index.expect("index not filled");
        }
        if let Some(name) = &self.name {
            sym_copy.st_name = strtab
                .offset_for_string(&name)
                .expect("name for symbol not found in strtab");
        }

        sym_copy
    }

    pub fn section_name(&self) -> Option<String> {
        self.section.as_ref().map(|s| s.borrow().name.clone())
    }
}
