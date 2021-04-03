use goblin::{
    elf::{self, section_header::*},
    elf64::sym::STT_SECTION,
    Object,
};
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

mod reloc;
mod section;
mod strtab;
mod symbol;
mod symtab;

pub use reloc::{Reloc, RelocSection};
pub use section::Section;
pub use strtab::Strtab;
pub use symbol::Symbol;
pub use symtab::Symtab;

#[derive(Debug, Clone)]
pub struct Elf {
    pub sections: Vec<Rc<RefCell<Section>>>,
    pub symtab: Symtab,
    pub reloc_sections: Vec<RelocSection>,
}

impl Elf {
    pub fn new(bytes: &Vec<u8>) -> Elf {
        let elf = match Object::parse(&bytes).expect("parsing object file failed") {
            Object::Elf(elf) => elf,
            _ => panic!("invalid file type"),
        };

        /* TODO
        assert!(elf.is_object_file());
        assert!(elf.little_endian);
        assert!(!elf.is_64);
        */

        let mut sections = BTreeMap::new();
        let mut reloc_sections = Vec::new();

        for (ix, header) in elf.section_headers.iter().enumerate() {
            let section = Section::extract(header, &elf.shdr_strtab, bytes);
            sections.insert(ix, Rc::new(RefCell::new(section)));
        }

        let symtab = Symtab::new(&elf.syms, &elf.strtab, &sections);

        for (section_ix, relocs) in elf.shdr_relocs.iter() {
            let header = elf
                .section_headers
                .get(*section_ix)
                .expect("invalid section index");

            let index_of_relocated_section = header.sh_info;

            let section = sections
                .get(&(index_of_relocated_section as usize))
                .map(|rc| rc.clone())
                .expect("relocated section has invalid index");

            let reloc_section = RelocSection::new(section, relocs.clone(), &symtab);
            reloc_sections.push(reloc_section);
        }

        Elf {
            sections: sections.values().cloned().collect(),
            reloc_sections,
            symtab,
        }
    }

    pub fn section_by_name(&self, name: &str) -> Option<Rc<RefCell<Section>>> {
        self.sections
            .iter()
            .filter(|s| s.borrow().name == name)
            .cloned()
            .next()
    }

    pub fn reloc_section_by_name(&self, name: &str) -> Option<RelocSection> {
        self.reloc_sections
            .iter()
            .filter(|s| s.target.borrow().name == name)
            .cloned()
            .next()
    }

    pub fn section_symbol_by_name(&self, name: &str) -> Option<Rc<RefCell<Symbol>>> {
        self.symtab
            .symbols
            .iter()
            .filter(|s| {
                let sym: &elf::Sym = &s.borrow().sym;
                sym.st_type() == STT_SECTION
            })
            .filter(|s| s.borrow().section_name() == Some(name.to_string()))
            .cloned()
            .next()
    }

    pub fn add_suffix_to_section_names(&mut self, suffix: &str) {
        for section in self.sections.iter_mut() {
            section.borrow_mut().name.push_str(suffix);
        }
    }

    // gets sections that will be copied during serialization process
    fn filtered_sections(&self) -> Vec<Rc<RefCell<Section>>> {
        self.sections
            .iter()
            .filter(|section| {
                section.borrow().header.is_alloc() || section.borrow().header.sh_type == SHT_NULL
            })
            .filter(|section| !section.borrow().header.is_relocation())
            .filter(|section| section.borrow().header.sh_type != SHT_NOTE)
            .cloned()
            .collect()
    }

    fn generate_shstrtab<'a>(
        &self,
        sections: impl Iterator<Item = &'a RefCell<Section>>,
    ) -> Strtab {
        use std::iter::once;

        let section_names = sections
            .map(|section| section.borrow().name.clone())
            .chain(once(".shstrtab".to_string()));

        Strtab::new(section_names)
    }

    pub fn merge(&mut self, other: Elf) {
        self.symtab.extend(other.symtab.symbols);
        self.sections.extend(other.sections);
        self.reloc_sections.extend(other.reloc_sections);
    }

    pub fn serialize(&self) -> Vec<u8> {
        let strtab = self.symtab.generate_strtab();
        let strtab_section = Rc::new(RefCell::new(strtab.to_section(".strtab".into())));

        // gather all sections (convert RelocSection, Symbols, ... to Section)
        let mut section_index_generator = 0;
        let mut sections = self.filtered_sections();
        sections.push(strtab_section.clone());

        for section in sections.iter() {
            section.borrow_mut().index = Some(section_index_generator);
            section_index_generator += 1;
        }

        // generate symtab
        let strtab_section_index = strtab_section
            .borrow()
            .index
            .expect("strtab should have index now");
        let symtab_section = Rc::new(RefCell::new(
            self.symtab.to_section(strtab_section_index, &strtab),
        ));
        symtab_section.borrow_mut().index = Some(section_index_generator);
        section_index_generator += 1;
        sections.push(symtab_section.clone());

        // generate reloc sections
        for reloc_section in &self.reloc_sections {
            let mut section = reloc_section.to_section(&symtab_section.borrow());
            section.index = Some(section_index_generator);
            section_index_generator += 1;

            sections.push(Rc::new(RefCell::new(section)));
        }

        // generate shstrtab section
        let shstrtab = self.generate_shstrtab(sections.iter().map(|s| s.as_ref()));
        let mut shstrtab_section = shstrtab.to_section(".shstrtab".into());
        shstrtab_section.index = Some(section_index_generator);
        //section_index_generator += 1;
        sections.push(Rc::new(RefCell::new(shstrtab_section)));

        Self::serialize_sections(&sections, &shstrtab)
    }

    fn serialize_sections(sections: &Vec<Rc<RefCell<Section>>>, strtab: &Strtab) -> Vec<u8> {
        use goblin::container::{Container, Ctx, Endian};
        use scroll::Pwrite;

        // ceate hader now, update later
        let mut elf_header = Self::create_header64();

        let mut buf = Vec::new();
        buf.resize(elf_header.e_ehsize as usize, 0);

        let mut headers: Vec<elf::SectionHeader> = Vec::with_capacity(sections.len());

        for section in sections.iter() {
            let offset = section.borrow().serialize(&mut buf);

            let mut header = section.borrow().header.clone();
            header.sh_offset = offset as u64;
            header.sh_name = strtab
                .offset_for_string(&section.borrow().name)
                .expect("section should have valid name"); // TODO sure?
            headers.push(header);
        }

        // alignment
        while buf.len() % 8 != 0 {
            buf.push(0);
        }

        let section_headers_offset = buf.len();

        let mut section_bytes = [0u8; section_header64::SIZEOF_SHDR];
        let ctx64 = Ctx::new(Container::Big, Endian::Little);
        for header in &headers {
            section_bytes.pwrite_with(header.clone(), 0, ctx64).unwrap();
            buf.extend_from_slice(&section_bytes);
        }

        elf_header.e_shoff = section_headers_offset as u64;
        elf_header.e_shnum = headers.len() as u16;

        elf_header.e_shstrndx = sections
            .iter()
            .filter(|s| s.borrow().name == ".shstrtab")
            .next()
            .expect("there should be .shstrtab section")
            .borrow()
            .index
            .expect(".shstrtab index should be filled") as u16;

        // update header bytes
        buf.pwrite_with(elf_header, 0, Endian::Little).unwrap();

        buf
    }

    fn create_header64() -> elf::Header {
        use goblin::container::{Container, Ctx, Endian};
        use goblin::elf::header::*;

        let ctx64 = Ctx::new(Container::Big, Endian::Little);
        let mut h64 = elf::Header::new(ctx64);
        h64.e_machine = EM_X86_64;
        h64.e_type = ET_REL;
        h64.e_shentsize = section_header64::SIZEOF_SHDR as u16;

        h64
    }
}

impl Default for Elf {
    fn default() -> Self {
        Self {
            sections: Vec::new(),
            symtab: Default::default(),
            reloc_sections: Vec::new(),
        }
    }
}

pub fn create_st_info(bind: u8, symbol_type: u8) -> u8 {
    (bind << 4) + (symbol_type & 0xf)
}
