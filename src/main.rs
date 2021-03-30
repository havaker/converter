use goblin::{
    elf::{self, Elf},
    error,
    strtab::Strtab,
    Object,
};
use std::collections::HashMap;
use std::ffi::CString;
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

use goblin::elf::sym::*;
use goblin::{
    container::{Container, Ctx, Endian},
    elf::{header::*, section_header::*},
};
use scroll::Pwrite;
use std::io::Write;

#[derive(Debug, Clone)]
struct Section {
    header: SectionHeader,
    name: String,
    content: Vec<u8>,
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
    name: String,
    section: Option<Rc<Section>>,
    sym: Sym,
}

// An object file can have more than one section with the same name.
#[derive(Debug, Clone)]
struct Sections {
    sections: BTreeMap<usize, Rc<Section>>,
    symbols: Vec<Symbol>,
}

impl Sections {
    fn new(elf: &Elf, bytes: &Vec<u8>) -> Sections {
        let mut sections = BTreeMap::new();
        let mut symbols = Vec::new();

        for (ix, header) in elf.section_headers.iter().enumerate() {
            let section = Section::extract(header, &elf.shdr_strtab, bytes);
            sections.insert(ix, Rc::new(section));
        }

        for sym in elf.syms.iter() {
            let name = match sym.st_name {
                0 => String::new(),
                _ => elf
                    .strtab
                    .get(sym.st_name)
                    .expect("invalid shstrtab index")
                    .expect("invalid section name")
                    .to_string(),
            };

            let section = sections.get(&sym.st_shndx).map(|rc| rc.clone());

            let symbol = Symbol { name, section, sym };
            symbols.push(symbol);
        }

        Sections { sections, symbols }
    }
}

fn process(elf: Elf, buffer: &Vec<u8>) {
    let sections = Sections::new(&elf, buffer);
    dbg!(&sections.symbols);
}
