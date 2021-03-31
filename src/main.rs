use goblin::elf::section_header::*;
use goblin::{elf, error, strtab, Object};
use std::{cell::RefCell, collections::HashMap, ffi::CString, fs, io::Write};
use std::{collections::BTreeMap, rc::Rc};

fn main() -> error::Result<()> {
    let buffer = fs::read("reloc.o")?;
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
    // sh_name, sh_link and sh_info are invalid
    header: elf::SectionHeader,

    // for SHT_NOBITS section type, content.len() is 0 and header.sh_size >= 0
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

#[derive(Debug, Clone)]
struct RelocSection {
    target: Rc<Section>,
    relocs: Vec<Reloc>,
}

impl RelocSection {
    fn new(target: Rc<Section>, reloc_section: &elf::RelocSection, symtab: &Symtab) -> Self {
        let mut relocs = Vec::with_capacity(reloc_section.len());

        for reloc in reloc_section.iter() {
            let symbol = symtab.symbols.get(reloc.r_sym).expect("").clone();
            let r = Reloc { reloc, symbol };
            relocs.push(r);
        }

        RelocSection { target, relocs }
    }

    fn to_section(&self, symtab: &Section) -> Section {
        use goblin::container::{Container, Ctx, Endian};
        use scroll::Pwrite;

        let name = format!(".rela{}", self.target.name);

        let relocs = self.relocs.iter().map(|r| {
            let mut updated_reloc = r.reloc.clone();
            updated_reloc.r_sym = r
                .symbol
                .index
                .borrow()
                .expect("symbol should have index assigned");

            updated_reloc
        });

        let mut content = Vec::new();

        let is_rela = true;
        let ctx64 = Ctx::new(Container::Big, Endian::Little);
        let mut reloc_bytes = [0u8; elf::reloc::reloc64::SIZEOF_RELA];
        for reloc in relocs {
            reloc_bytes.pwrite_with(reloc, 0, (is_rela, ctx64)).unwrap();
            content.extend_from_slice(&reloc_bytes);
        }

        let mut header = elf::SectionHeader::new();
        header.sh_type = SHT_RELA;
        header.sh_size = content.len() as u64;
        header.sh_entsize = elf::reloc::reloc64::SIZEOF_RELA as u64;

        // The section header index of the section to which the relocation applies
        header.sh_info = self
            .target
            .index
            .borrow()
            .expect("reloc target should have index assigned") as u32;
        // The section header index of the associated symbol table
        header.sh_link = symtab
            .index
            .borrow()
            .expect("symtab associated with reloc section should have index assigned")
            as u32;
        // TODO sh_addralign: 2 << 8??
        header.sh_addralign = 8;
        header.sh_flags = SHF_INFO_LINK as u64;

        Section {
            header,
            name,
            content,
            index: RefCell::new(None),
        }
    }
}

struct Strtab {
    strings: Vec<String>,
    offsets: HashMap<String, usize>,
}

impl Strtab {
    fn new(iter: impl Iterator<Item = String>) -> Self {
        let mut strings: Vec<String> = vec![String::new()];
        strings.extend(iter);

        let mut index_generator = 0;
        let mut offsets = HashMap::new();

        for string in strings.iter() {
            offsets.insert(string.clone(), index_generator);
            index_generator += string.len() + 1;
        }

        Strtab { strings, offsets }
    }

    fn offset_for_string(&self, string: &str) -> Option<usize> {
        self.offsets.get(string).cloned()
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

        Section {
            header,
            name,
            content,
            index: RefCell::new(None),
        }
    }
}

#[derive(Debug, Clone)]
struct Symtab {
    symbols: Vec<Rc<Symbol>>,
}

// TODO sort, local first

impl Symtab {
    fn new(
        syms: &elf::Symtab,
        strtab: &strtab::Strtab,
        sections: &BTreeMap<usize, Rc<Section>>,
    ) -> Self {
        let mut symbols = Vec::new();

        for sym in syms.iter() {
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
                index: RefCell::new(None),
            };
            symbols.push(Rc::new(symbol));
        }

        Symtab { symbols }
    }

    fn generate_strtab(&self) -> Strtab {
        let symbol_names = self
            .symbols
            .iter()
            .filter_map(|symbol| symbol.name.as_ref())
            .cloned();

        Strtab::new(symbol_names)
    }

    fn update_indexes(&self) {
        let mut index_generator = 0;

        for symbol in self.symbols.iter() {
            let mut index = symbol.index.borrow_mut();
            *index = Some(index_generator);

            index_generator += 1;
        }
    }

    fn to_section(&self, strtab: Rc<Section>) -> Section {
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
        header.sh_addralign = 8;
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
}

#[derive(Debug, Clone)]
struct Elf {
    sections: Vec<Rc<Section>>,
    symtab: Symtab,
    reloc_sections: Vec<RelocSection>,
}

impl Elf {
    fn new(elf: &elf::Elf, bytes: &Vec<u8>) -> Elf {
        let mut sections = BTreeMap::new();
        let mut reloc_sections = Vec::new();

        for (ix, header) in elf.section_headers.iter().enumerate() {
            let section = Section::extract(header, &elf.shdr_strtab, bytes);
            sections.insert(ix, Rc::new(section));
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

    fn generate_shstrtab<'a>(&self, sections: impl Iterator<Item = &'a Section>) -> Strtab {
        use std::iter::once;

        let section_names = sections
            .map(|section| &section.name)
            .cloned()
            .chain(once(".shstrtab".to_string()));

        Strtab::new(section_names)
    }

    fn serialize(&self) -> Vec<u8> {
        use goblin::container::Endian;
        use scroll::Pwrite;

        let mut buf = Vec::new();

        // Create hader now, update later
        let mut header = Self::create_header64();
        buf.resize(header.e_ehsize as usize, 0);

        let strtab = self.symtab.generate_strtab();
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

        // generate symtab
        self.symtab.update_indexes();
        let symtab_section = Rc::new(self.symtab.to_section(strtab_section));
        *symtab_section.index.borrow_mut() = Some(section_index_generator);
        section_index_generator += 1;
        sections.push(symtab_section.clone());

        // generate reloc sections
        for reloc_section in &self.reloc_sections {
            let section = reloc_section.to_section(&symtab_section);
            *section.index.borrow_mut() = Some(section_index_generator);
            section_index_generator += 1;

            sections.push(Rc::new(section));
        }

        // generate shstrtab section
        let shstrtab = self.generate_shstrtab(sections.iter().map(|s| s.as_ref()));
        let shstrtab_section = shstrtab.to_section(".shstrtab".into());
        *shstrtab_section.index.borrow_mut() = Some(section_index_generator);
        //section_index_generator += 1;
        sections.push(Rc::new(shstrtab_section));

        Self::serialize_sections(&sections, &shstrtab, &mut buf, &mut header);

        // Update header bytes
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
    let section_names = &e
        .sections
        .iter()
        .map(|s| s.name.clone())
        .collect::<Vec<_>>();
    dbg!(section_names);

    let res = e.serialize();
    let mut f = fs::File::create("con.o").unwrap();
    f.write(&res).unwrap();
}
