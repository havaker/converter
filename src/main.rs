use goblin::elf::section_header::*;
use goblin::{elf, error, strtab, Object};
use std::{cell::RefCell, collections::HashMap, ffi::CString, fs, io::Write};
use std::{collections::BTreeMap, rc::Rc};

fn main() -> error::Result<()> {
    let buffer = fs::read("asdf.o")?;
    match Object::parse(&buffer)? {
        Object::Elf(elf) => {
            process(elf, &buffer);
        }
        _ => (),
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct Section {
    header: elf::SectionHeader,
    content: Vec<u8>,

    // An object file can have more than one section with the same name.
    name: String,

    // Computed during serialization process
    index: RefCell<Option<usize>>,
}

impl Section {
    fn extract(header: &SectionHeader, strtab: &strtab::Strtab, bytes: &Vec<u8>) -> Section {
        let range = match header.sh_type {
            SHT_NOBITS => 0..0,
            _ => (header.sh_offset as usize)..((header.sh_offset + header.sh_size) as usize),
        };

        let name = strtab
            .get(header.sh_name)
            .expect("invalid shstrtab index")
            .expect("invalid section name")
            .to_string();

        Section {
            header: header.clone(),
            content: Vec::from(&bytes[range]),
            name,
            index: None.into(),
        }
    }

    fn serialize(&self, buf: &mut Vec<u8>) -> usize {
        // align section
        if self.header.sh_addralign != 0 {
            while buf.len() % self.header.sh_addralign as usize != 0 {
                buf.push(0);
            }
        }

        let offset = buf.len();
        buf.extend_from_slice(&self.content);

        offset
    }
}

#[derive(Debug, Clone)]
struct Symbol {
    name: Option<String>,
    section: Option<Rc<Section>>,
    sym: elf::Sym,

    // Computed during serialization process
    index: RefCell<Option<usize>>,
}

impl Symbol {
    fn get_sym_with_updated_section_index(&self) -> elf::Sym {
        let mut sym_copy = self.sym.clone();
        if let Some(section) = &self.section {
            sym_copy.st_shndx = section.index.borrow().expect("index not filled");
        }

        sym_copy
    }
}

#[derive(Debug, Clone)]
struct Reloc {
    reloc: elf::Reloc,
    symbol: Rc<Symbol>,
}

// TODO into Section
#[derive(Debug, Clone)]
struct RelocSection {
    target: Rc<Section>,
    relocs: Vec<Reloc>,
}

impl RelocSection {
    fn new(
        target: Rc<Section>,
        reloc_section: &elf::RelocSection,
        symbols: &Vec<Rc<Symbol>>,
    ) -> Self {
        let mut relocs = Vec::with_capacity(reloc_section.len());

        for reloc in reloc_section.iter() {
            let symbol = symbols.get(reloc.r_sym).expect("").clone();
            let r = Reloc { reloc, symbol };
            relocs.push(r);
        }

        RelocSection { target, relocs }
    }
}

struct Strtab {
    strings: Vec<String>,
    position: HashMap<String, usize>,
}

impl Strtab {
    fn new(iter: impl Iterator<Item = String>) -> Self {
        let mut strings: Vec<String> = vec![String::new()];
        strings.extend(iter);

        let mut index_generator = 0;
        let mut position = HashMap::new();

        for string in strings.iter() {
            position.insert(string.clone(), index_generator);
            index_generator += string.len() + 1;
        }

        Strtab { strings, position }
    }

    fn offset_for_string(&self, string: &str) -> Option<usize> {
        self.position.get(string).cloned()
    }

    fn to_section(&self, name: String) -> Section {
        let content = self
            .strings
            .iter()
            .map(|s| {
                CString::new(s.clone())
                    .expect("internal null in strtab string")
                    .into_bytes_with_nul()
            })
            .flatten()
            .collect::<Vec<_>>();

        let mut header = elf::SectionHeader::new();
        header.sh_type = SHT_STRTAB;
        header.sh_size = content.len() as u64;
        header.sh_addralign = 1;
        header.sh_flags = 0;
        header.sh_name = 0;

        Section {
            header,
            name,
            content,
            index: RefCell::new(None),
        }
    }
}

#[derive(Debug, Clone)]
struct Elf {
    sections: Vec<Rc<Section>>,
    symbols: Vec<Rc<Symbol>>,
    reloc_sections: Vec<RelocSection>,
}

impl Elf {
    fn new(elf: &elf::Elf, bytes: &Vec<u8>) -> Elf {
        let mut sections = BTreeMap::new();
        let mut symbols = Vec::new();
        let mut reloc_sections = Vec::new();

        for (ix, header) in elf.section_headers.iter().enumerate() {
            let section = Section::extract(header, &elf.shdr_strtab, bytes);
            sections.insert(ix, Rc::new(section));
        }

        for sym in elf.syms.iter() {
            let name = match sym.st_name {
                0 => None,
                _ => Some(
                    elf.strtab
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
                index: RefCell::new(None),
            };
            symbols.push(Rc::new(symbol));
        }

        for (section_ix, relocs) in elf.shdr_relocs.iter() {
            let section = sections
                .get(section_ix)
                .map(|rc| rc.clone())
                .expect("invalid section index");

            let reloc_section = RelocSection::new(section, relocs.clone(), &symbols);
            reloc_sections.push(reloc_section);
        }

        Elf {
            sections: sections.values().cloned().collect(),
            symbols,
            reloc_sections,
        }
    }

    // TODO
    fn filtered_sections(&self) -> Vec<Rc<Section>> {
        self.sections
            .iter()
            .filter(|section| section.header.is_alloc() || section.header.sh_type == SHT_NULL)
            .filter(|section| !section.header.is_relocation())
            .filter(|section| section.header.sh_type != SHT_NOTE)
            .cloned()
            .collect()
    }

    fn generate_strtab(&self) -> Strtab {
        let symbol_names = self
            .symbols
            .iter()
            .filter_map(|symbol| symbol.name.as_ref())
            .cloned();

        Strtab::new(symbol_names)
    }

    fn generate_shstrtab<'a>(&self, sections: impl Iterator<Item = &'a Section>) -> Strtab {
        use std::iter::once;

        let section_names = sections
            .map(|section| &section.name)
            .cloned()
            .chain(once(".shstrtab".to_string()));

        Strtab::new(section_names)
    }

    fn symtab_to_section(&self, strtab: Rc<Section>) -> Section {
        use goblin::container::{Container, Ctx, Endian};
        use scroll::Pwrite;

        let syms = self
            .symbols
            .iter()
            .map(|symbol| symbol.get_sym_with_updated_section_index())
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
        header.sh_addralign = 4; // TODO validate
        header.sh_entsize = elf::sym::sym64::SIZEOF_SYM as u64;
        header.sh_link = strtab
            .index
            .borrow()
            .expect("strtab section should have index") as u32;

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
            index: RefCell::new(None),
        }
    }

    fn generate_symtab_indexes(&self) {
        let mut index_generator = 0;

        for symbol in self.symbols.iter() {
            let mut index = symbol.index.borrow_mut();
            *index = Some(index_generator);

            index_generator += 1;
        }
    }

    fn serialize(&self) -> Vec<u8> {
        use goblin::container::Endian;
        use scroll::Pwrite;

        let mut buf = Vec::new();

        // Create hader now, update later
        let mut header = Self::create_header64();
        buf.resize(header.e_ehsize as usize, 0);

        let strtab = self.generate_strtab();
        let strtab_section = Rc::new(strtab.to_section(".strtab".into()));

        // gather all sections (convert RelocSection, Symbols, ... to Section)
        let mut section_index_generator = 0;
        let mut sections = self.filtered_sections();
        sections.push(strtab_section.clone());

        for section in sections.iter() {
            let mut index = section.index.borrow_mut();
            *index = Some(section_index_generator);

            section_index_generator += 1;
        }

        self.generate_symtab_indexes();
        let symtab_section = self.symtab_to_section(strtab_section);
        *symtab_section.index.borrow_mut() = Some(section_index_generator);
        section_index_generator += 1;
        sections.push(Rc::new(symtab_section));

        let shstrtab = self.generate_shstrtab(sections.iter().map(|s| s.as_ref()));
        let shstrtab_section = shstrtab.to_section(".shstrtab".into());
        *shstrtab_section.index.borrow_mut() = Some(section_index_generator);
        //section_index_generator += 1;
        sections.push(Rc::new(shstrtab_section));

        // TODO reloc section
        Self::serialize_sections(&sections, &shstrtab, &mut buf, &mut header);

        buf.pwrite_with(header, 0, Endian::Little).unwrap();

        buf
    }

    fn serialize_sections(
        sections: &Vec<Rc<Section>>,
        strtab: &Strtab,
        buf: &mut Vec<u8>,
        elf_header: &mut elf::Header,
    ) {
        use goblin::container::{Container, Ctx, Endian};
        use scroll::Pwrite;

        let mut headers: Vec<elf::SectionHeader> = Vec::with_capacity(sections.len());

        for section in sections.iter() {
            let offset = section.serialize(buf);

            let mut header = section.header.clone();
            header.sh_offset = offset as u64;
            header.sh_name = strtab
                .offset_for_string(&section.name)
                .expect("section should have valid name"); // TODO sure?
            headers.push(header);
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
            .filter(|s| s.name == ".shstrtab")
            .next()
            .expect("there should be .shstrtab section")
            .index
            .borrow()
            .expect(".shstrtab index should be filled") as u16;
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

fn process(elf: elf::Elf, buffer: &Vec<u8>) {
    let e = Elf::new(&elf, buffer);
    dbg!(&e.sections);

    let res = e.serialize();
    let mut f = fs::File::create("con.o").unwrap();
    f.write(&res).unwrap();
}
