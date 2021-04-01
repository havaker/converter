use goblin::{
    elf::{self, section_header::*},
    elf64::sym::{STB_GLOBAL, STB_LOCAL, STB_WEAK, STT_FUNC, STT_SECTION, STV_DEFAULT},
    error, Object,
};
use std::{cell::RefCell, env, ffi::OsString, fs, rc::Rc};

mod rel;
use rel::*;

// TODO R_X86_64_32 or R_X86_64_32S

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
    let mut e = rel::Elf::new(&elf, buffer);

    let section_names = &e
        .sections
        .iter()
        .map(|s| s.borrow().name.clone())
        .collect::<Vec<_>>();

    //dbg!(&e.reloc_sections);
    //dbg!(&section_names);

    for section in &mut e.reloc_sections {
        section.to_rela();
    }

    let is_global_func = |symbol: &&Rc<RefCell<Symbol>>| {
        let sym: &elf::Sym = &symbol.borrow().sym;
        let is_function = sym.st_type() == STT_FUNC;
        let is_global = sym.st_bind() == STB_GLOBAL || sym.st_bind() == STB_WEAK;

        is_function && is_global
    };

    let mut global_func_symbols = e
        .symtab
        .symbols
        .iter()
        .filter(is_global_func)
        .cloned()
        .collect::<Vec<_>>();

    let mut thunkins = Vec::new();

    for func in &mut global_func_symbols {
        let thunkin = create_thunkin(func.clone());
        thunkins.push(thunkin);

        let mut sym = func.borrow_mut();
        sym.sym.st_info = create_st_info(STB_LOCAL, STT_FUNC);
    }

    for thunkin in thunkins.into_iter() {
        e.sections.push(thunkin.section);
        e.reloc_sections.push(thunkin.reloc_section);
        e.symtab.extend(thunkin.symbols);
    }

    // dbg!(&func_symbols);

    e.serialize()
}

struct Thunkin {
    section: Rc<RefCell<Section>>,
    reloc_section: RelocSection,
    symbols: Vec<Rc<RefCell<Symbol>>>,
}

fn create_thunkin(func_symbol: Rc<RefCell<Symbol>>) -> Thunkin {
    let sym_name = func_symbol
        .borrow()
        .name
        .clone()
        .expect("name of function should not be none");
    println!("crating thunkin for {}", sym_name);

    let content = fs::read("../call32from64.text").unwrap();
    let content_len = content.len();

    for b in &content {
        print!("{:#04x} ", b)
    }
    println!();

    let mut header = elf::SectionHeader::new();
    header.sh_addralign = 8;
    header.sh_type = SHT_PROGBITS;
    header.sh_flags = (SHF_EXECINSTR | SHF_ALLOC) as u64;
    header.sh_size = content.len() as u64;
    header.sh_entsize = elf::reloc::reloc64::SIZEOF_RELA as u64;

    let section = Rc::new(RefCell::new(Section {
        header,
        content,
        name: format!(".{}.thunkin", &sym_name),
        index: None,
    }));

    let section_symbol = Rc::new(RefCell::new(Symbol {
        name: None,
        section: Some(section.clone()),
        sym: elf::Sym {
            st_name: 0,
            st_info: create_st_info(STB_LOCAL, STT_SECTION),
            st_other: STV_DEFAULT,
            st_shndx: 0,
            st_value: 0,
            st_size: content_len as u64,
        },
        index: None,
    }));

    let func64_symbol = Rc::new(RefCell::new(Symbol {
        name: Some(sym_name),
        section: Some(section.clone()),
        sym: elf::Sym {
            st_name: 0,
            st_info: create_st_info(STB_GLOBAL, STT_FUNC),
            st_other: STV_DEFAULT,
            st_shndx: 0,
            st_value: 0,
            st_size: content_len as u64,
        },

        index: None,
    }));

    let relocs = vec![
        Reloc {
            reloc: elf::Reloc {
                r_offset: 0x1d,
                r_addend: Some(0x4a),
                r_sym: 0x1,
                r_type: 11,
            },
            symbol: section_symbol.clone(),
        },
        Reloc {
            reloc: elf::Reloc {
                r_offset: 0x28,
                r_addend: Some(-4),
                r_sym: 0x7,
                r_type: 4,
            },
            symbol: func_symbol.clone(),
        },
        Reloc {
            reloc: elf::Reloc {
                r_offset: 0x2e,
                r_addend: Some(0x52),
                r_sym: 0x1,
                r_type: 10,
            },
            symbol: section_symbol.clone(),
        },
        Reloc {
            reloc: elf::Reloc {
                r_offset: 0x4a,
                r_addend: Some(0x21),
                r_sym: 0x1,
                r_type: 10,
            },
            symbol: section_symbol.clone(),
        },
        Reloc {
            reloc: elf::Reloc {
                r_offset: 0x52,
                r_addend: Some(0x32),
                r_sym: 0x1,
                r_type: 10,
            },
            symbol: section_symbol.clone(),
        },
    ];

    let reloc_section = RelocSection {
        target: section.clone(),
        relocs,
    };

    Thunkin {
        section,
        reloc_section,
        symbols: vec![func64_symbol, func_symbol, section_symbol],
    }
}

fn create_st_info(bind: u8, symbol_type: u8) -> u8 {
    (bind << 4) + (symbol_type & 0xf)
}
