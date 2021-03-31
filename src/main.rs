use goblin::{
    elf::{
        self,
        reloc::{R_386_32, R_386_PC32, R_386_PLT32, R_X86_64_32, R_X86_64_PC32},
        section_header::*,
    },
    elf64::sym::STT_FILE,
    error, strtab, Object,
};

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    convert::TryInto,
    env,
    ffi::{CString, OsString},
    fs,
    rc::Rc,
};

fn main() -> error::Result<()> {
    let args: Vec<OsString> = env::args_os().collect();
    if args.len() != 3 {
        panic!("invalid argument count");
    }

    let input_path = &args[1];
    let output_path = &args[2];
    dbg!(&args);

    let buffer = fs::read(input_path)?;

    let converted = match Object::parse(&buffer)? {
        Object::Elf(elf) => convert(elf, &buffer),
        _ => panic!("invalid file type"),
    };

    fs::write(output_path, &converted)?;

    Ok(())
}

fn convert(elf: elf::Elf, buffer: &Vec<u8>) -> Vec<u8> {
    let mut e = Elf::new(&elf, buffer);

    let section_names = &e
        .sections
        .iter()
        .map(|s| s.borrow().name.clone())
        .collect::<Vec<_>>();

    dbg!(&e.sections);
    dbg!(&section_names);

    for section in &mut e.reloc_sections {
        section.to_rela();
    }

    e.serialize()
}

#[derive(Debug, Clone)]
struct Section {
    // sh_name, sh_link and sh_info are invalid
    header: elf::SectionHeader,

    // for SHT_NOBITS section type, content.len() is 0 and header.sh_size >= 0
    content: Vec<u8>,

    // an object file can have more than one section with the same name.
    name: String,

    // computed during serialization process
    index: Option<usize>,
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
            index: None,
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
    section: Option<Rc<RefCell<Section>>>,
    sym: elf::Sym,

    // computed during serialization process
    index: Option<usize>,
}

impl Symbol {
    fn get_sym_with_updated_indexes(&self, strtab: &Strtab) -> elf::Sym {
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
}

#[derive(Debug, Clone)]
struct Reloc {
    reloc: elf::Reloc,
    symbol: Rc<RefCell<Symbol>>,
}

impl Reloc {
    fn update_to_rela(&mut self, section: &mut Section) {
        match self.reloc.r_type {
            R_386_32 => {
                self.reloc.r_type = R_X86_64_32;
            }
            R_386_PC32 | R_386_PLT32 => {
                self.reloc.r_type = R_X86_64_PC32;
            }
            _ => {
                eprintln!("unknown reloc type: {:?}", self.reloc.r_type);
                return;
            }
        };

        let offset = self.reloc.r_offset as usize;
        let size = 4;
        let range = offset..(offset + size);

        let addend_slice = section
            .content
            .get_mut(range)
            .expect("incorrect reloc range");
        let addend = u32::from_le_bytes(addend_slice.as_ref().try_into().unwrap()) as i64;

        self.reloc.r_addend = Some(addend);
        for byte in addend_slice.iter_mut() {
            *byte = 0;
        }
    }
}

#[derive(Debug, Clone)]
struct RelocSection {
    target: Rc<RefCell<Section>>,
    relocs: Vec<Reloc>,
}

impl RelocSection {
    fn new(
        target: Rc<RefCell<Section>>,
        reloc_section: &elf::RelocSection,
        symtab: &Symtab,
    ) -> Self {
        let mut relocs = Vec::with_capacity(reloc_section.len());

        for reloc in reloc_section.iter() {
            let symbol = symtab
                .get_using_orginal_index(reloc.r_sym)
                .expect("failed to find symbol"); // TODO ups
            let r = Reloc { reloc, symbol };
            relocs.push(r);
        }

        RelocSection { target, relocs }
    }

    fn to_rela(&mut self) {
        for r in &mut self.relocs {
            r.update_to_rela(&mut self.target.borrow_mut());
        }
    }

    fn to_section(&self, symtab: &Section) -> Section {
        use goblin::container::{Container, Ctx, Endian};
        use scroll::Pwrite;

        let name = format!(".rela{}", self.target.borrow().name);
        dbg!(&name);

        let relocs = self.relocs.iter().map(|r| {
            let mut updated_reloc = r.reloc.clone();
            updated_reloc.r_sym = r
                .symbol
                .borrow()
                .index
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

        // the section header index of the section to which the relocation applies
        header.sh_info = self
            .target
            .borrow()
            .index
            .expect("reloc target should have index assigned") as u32;
        // the section header index of the associated symbol table
        header.sh_link = symtab
            .index
            .expect("symtab associated with reloc section should have index assigned")
            as u32;
        // TODO sh_addralign: 2 << 8??
        header.sh_addralign = 8;
        header.sh_flags = SHF_INFO_LINK as u64;

        Section {
            header,
            name,
            content,
            index: None,
        }
    }
}

#[derive(Debug, Clone)]
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
            index: None,
        }
    }
}

#[derive(Debug, Clone)]
struct Symtab {
    symbols: Vec<Rc<RefCell<Symbol>>>,
    orginal_index_to_new: HashMap<usize, usize>,
}

// TODO sort, local first

impl Symtab {
    fn new(
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

    fn get_using_orginal_index(&self, index: usize) -> Option<Rc<RefCell<Symbol>>> {
        let new_index = self
            .orginal_index_to_new
            .get(&index)
            .expect("cannnot find new index");

        self.symbols.get(*new_index).cloned()
    }

    fn generate_strtab(&self) -> Strtab {
        let symbol_names = self
            .symbols
            .iter()
            .filter_map(|symbol| symbol.borrow().name.clone());

        Strtab::new(symbol_names)
    }

    fn update_indexes(&self) {
        let mut index_generator = 0;

        for symbol in self.symbols.iter() {
            symbol.borrow_mut().index = Some(index_generator);
            index_generator += 1;
        }
    }

    fn to_section(&self, strtab_index: usize, strtab: &Strtab) -> Section {
        use goblin::container::{Container, Ctx, Endian};
        use scroll::Pwrite;

        let syms = self
            .symbols
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
}

#[derive(Debug, Clone)]
struct Elf {
    sections: Vec<Rc<RefCell<Section>>>,
    symtab: Symtab,
    reloc_sections: Vec<RelocSection>,
}

impl Elf {
    fn new(elf: &elf::Elf, bytes: &Vec<u8>) -> Elf {
        assert!(elf.is_object_file());
        assert!(elf.little_endian);
        assert!(!elf.is_64);

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

    // TODO
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

    fn serialize(&self) -> Vec<u8> {
        let strtab = self.symtab.generate_strtab();
        dbg!(&strtab);
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
        self.symtab.update_indexes();
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
