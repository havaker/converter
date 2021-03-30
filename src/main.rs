use goblin::elf::section_header::*;
use goblin::{elf, error, strtab::Strtab, Object};
use std::fs;
use std::{collections::BTreeMap, rc::Rc};

fn main() -> error::Result<()> {
    let buffer = fs::read("ass.o")?;
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
}

impl Section {
    fn extract(header: &SectionHeader, strtab: &Strtab, bytes: &Vec<u8>) -> Section {
        let range = (header.sh_offset as usize)..((header.sh_offset + header.sh_size) as usize);
        let name = strtab
            .get(header.sh_name)
            .expect("invalid shstrtab index")
            .expect("invalid section name")
            .to_string();

        Section {
            header: header.clone(),
            content: Vec::from(&bytes[range]),
            name,
        }
    }
}

#[derive(Debug, Clone)]
struct Symbol {
    name: Option<String>,
    section: Option<Rc<Section>>,
    sym: elf::Sym,
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

#[derive(Debug, Clone)]
struct Elf {
    sections: BTreeMap<usize, Rc<Section>>,
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

            let symbol = Symbol { name, section, sym };
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
            sections,
            symbols,
            reloc_sections,
        }
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        buf
    }
}

fn process(elf: elf::Elf, buffer: &Vec<u8>) {
    let sections = Elf::new(&elf, buffer);
    dbg!(&sections.reloc_sections);
}
