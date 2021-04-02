use goblin::{
    elf::{self, section_header::*},
    elf64::sym::{STB_LOCAL, STT_FILE},
    strtab,
};
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    rc::Rc,
};

use super::{Section, Strtab, Symbol};

#[derive(Debug, Clone)]
pub struct Symtab {
    pub symbols: Vec<Rc<RefCell<Symbol>>>,
    orginal_index_to_new: HashMap<usize, usize>,
}

impl Symtab {
    pub fn new(
        syms: &elf::Symtab,
        strtab: &strtab::Strtab,
        sections: &BTreeMap<usize, Rc<RefCell<Section>>>,
    ) -> Self {
        let mut symbols = Vec::new();
        let mut orginal_index_to_new = HashMap::new();

        for (index, sym) in syms.iter().enumerate() {
            // ignore STT_FILE symbols
            if sym.st_type() == STT_FILE {
                continue;
            }

            let name = match sym.st_name {
                0 => None,
                _ => Some(
                    strtab
                        .get(sym.st_name)
                        .expect("invalid shstrtab index")
                        .expect("invalid section name")
                        .to_string(),
                ),
            };

            let section = sections.get(&sym.st_shndx).map(|rc| rc.clone());

            let symbol = Symbol {
                name,
                section,
                sym,
                index: None,
            };

            orginal_index_to_new.insert(index, symbols.len());
            symbols.push(Rc::new(RefCell::new(symbol)));
        }

        Symtab {
            symbols,
            orginal_index_to_new,
        }
    }

    pub fn extend(&mut self, symbols: Vec<Rc<RefCell<Symbol>>>) {
        self.symbols.extend(symbols);
    }

    pub fn get_using_orginal_index(&self, index: usize) -> Option<Rc<RefCell<Symbol>>> {
        let new_index = self
            .orginal_index_to_new
            .get(&index)
            .expect("cannnot find new index");

        self.symbols.get(*new_index).cloned()
    }

    pub fn generate_strtab(&self) -> Strtab {
        let symbol_names = self
            .symbols
            .iter()
            .filter_map(|symbol| symbol.borrow().name.clone());

        Strtab::new(symbol_names)
    }

    pub fn to_section(&self, strtab_index: usize, strtab: &Strtab) -> Section {
        use goblin::container::{Container, Ctx, Endian};
        use scroll::Pwrite;

        let sorted_symbols = self.get_sorted_symbols();

        Self::update_indexes(&sorted_symbols);

        let syms = sorted_symbols
            .iter()
            .map(|symbol| symbol.borrow().get_sym_with_updated_indexes(strtab))
            .collect::<Vec<_>>();

        let mut content = Vec::new();

        let ctx64 = Ctx::new(Container::Big, Endian::Little);
        let mut symbol_bytes = [0u8; elf::sym::sym64::SIZEOF_SYM];
        for sym in syms.iter().cloned() {
            symbol_bytes.pwrite_with(sym, 0, ctx64).unwrap();
            content.extend_from_slice(&symbol_bytes);
        }

        let mut header = elf::SectionHeader::new();
        header.sh_type = SHT_SYMTAB;
        header.sh_size = content.len() as u64;
        header.sh_addralign = 8;
        header.sh_entsize = elf::sym::sym64::SIZEOF_SYM as u64;
        header.sh_link = strtab_index as u32;

        // one greater than index of last local symbol
        header.sh_info = syms
            .iter()
            .filter(|s| s.st_bind() == elf::sym::STB_LOCAL)
            .enumerate()
            .map(|(index, _)| index + 1)
            .last()
            .unwrap_or(0) as u32;
        header.sh_flags = 0;

        Section {
            header,
            name: ".symtab".into(),
            content,
            index: None,
        }
    }

    fn update_indexes(symbols: &Vec<Rc<RefCell<Symbol>>>) {
        let mut index_generator = 0;

        for symbol in symbols.iter() {
            symbol.borrow_mut().index = Some(index_generator);
            index_generator += 1;
        }
    }

    fn get_sorted_symbols(&self) -> Vec<Rc<RefCell<Symbol>>> {
        let (mut local, mut other): (Vec<_>, Vec<_>) = self
            .symbols
            .iter()
            .cloned()
            .partition(|s| s.borrow().sym.st_bind() == STB_LOCAL);
        local.append(&mut other);

        local
    }
}

impl Default for Symtab {
    fn default() -> Self {
        Self {
            symbols: Vec::new(),
            orginal_index_to_new: HashMap::new(),
        }
    }
}
