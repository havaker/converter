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

    use keystone::*;
    let engine =
        Keystone::new(Arch::X86, Mode::MODE_64).expect("Could not initialize Keystone engine");
    engine
        .option(OptionType::SYNTAX, OptionValue::SYNTAX_GAS)
        .expect("Could not set option to nasm syntax");
    let prepend = engine
        .asm("pushq %rbx; pushq %rbp; pushq %r12; pushq %r13; pushq %r14; pushq %r15; subq $0x18, %rsp; movq %rdx, 8(%rsp); movl %esi, 4(%rsp); movl %edi, (%rsp)".to_string(), 0)
        .expect("Could not assemble").bytes;
    let append = engine
        .asm("mov %eax, %eax; shlq $32, %rdx; orq %rdx, %rax; addq $0x18, %rsp; popq %r15; popq %r14; popq %r13; popq %r12; popq %rbp; popq %rbx; retq".to_string(), 0)
        .expect("Could not assemble").bytes;

    for func in &mut global_func_symbols {
        let mut thunk = Thunk::new(func.clone());
        thunk.prepend_text(prepend.as_slice());
        thunk.append_text(append.as_slice());

        dbg!(&thunk.text_relocs);
        dbg!(&thunk.text);
        //let thunkin = create_thunkin(func.clone());
        thunkins.push(thunk);

        let mut sym = func.borrow_mut();
        sym.sym.st_info = create_st_info(STB_LOCAL, STT_FUNC);
    }

    for thunkin in thunkins.into_iter() {
        e.sections.push(thunkin.text);
        e.sections.push(thunkin.rodata);
        e.reloc_sections.push(thunkin.text_relocs);
        e.reloc_sections.push(thunkin.rodata_relocs);
        e.symtab.extend(thunkin.section_symbols);
        e.symtab.extend(vec![thunkin.generated_fun_symbol]);
        break;
    }

    // dbg!(&func_symbols);

    e.serialize()
}

#[derive(Debug, Clone)]
struct Thunk {
    text: Rc<RefCell<Section>>,
    text_relocs: RelocSection,

    rodata: Rc<RefCell<Section>>,
    rodata_relocs: RelocSection,

    section_symbols: Vec<Rc<RefCell<Symbol>>>,

    generated_fun_symbol: Rc<RefCell<Symbol>>,
}

impl Thunk {
    fn replace_fun_symbol(&mut self, fun_symbol: Rc<RefCell<Symbol>>) {
        for reloc in &mut self.text_relocs.relocs {
            if reloc.symbol.borrow().name.as_ref().map(|n| n.as_str()) == Some("fun") {
                reloc.symbol = fun_symbol.clone();
            }
        }
    }
    // func symbol
    // asm / signature
    fn new(fun_symbol: Rc<RefCell<Symbol>>) -> Self {
        let buffer = fs::read("../call32from64.o").unwrap();

        let elf = match Object::parse(&buffer).unwrap() {
            Object::Elf(elf) => Elf::new(&elf, &buffer),
            _ => panic!("invalid file type"),
        };

        let get_section = |name| {
            elf.sections
                .iter()
                .filter(|s| s.borrow().name == name)
                .cloned()
                .next()
                .unwrap()
        };

        let text = get_section(".text");
        let rodata = get_section(".rodata");

        let get_reloc_section = |name| {
            elf.reloc_sections
                .iter()
                .filter(|s| s.target.borrow().name == name)
                .cloned()
                .next()
                .unwrap()
        };

        let text_relocs = get_reloc_section(".text");
        /*
        text_relocs.relocs = text_relocs
            .relocs
            .into_iter()
            .filter(|r| false && r.symbol.borrow().name.is_none())
            .collect();
        */

        let rodata_relocs = get_reloc_section(".rodata");

        text.borrow_mut().name = ".text.thunkin".into();
        rodata.borrow_mut().name = ".rodata.thunkin".into();

        let section_symbols = elf
            .symtab
            .symbols
            .iter()
            .filter(|s| {
                let sym: &elf::Sym = &s.borrow().sym;
                sym.st_type() == STT_SECTION
            })
            .cloned()
            .collect::<Vec<_>>();

        let fun_name = fun_symbol.borrow().name.clone().unwrap();
        let generated_fun_symbol = Rc::new(RefCell::new(Symbol {
            name: Some(fun_name.clone()),
            section: Some(text.clone()),
            sym: elf::Sym {
                st_name: 0,
                st_info: create_st_info(STB_GLOBAL, STT_FUNC),
                st_other: STV_DEFAULT,
                st_shndx: 0,
                st_value: 0,
                st_size: text.borrow().content.len() as u64,
            },

            index: None,
        }));

        let mut thunk = Self {
            text,
            rodata,
            text_relocs,
            rodata_relocs,
            section_symbols,
            generated_fun_symbol,
        };

        thunk.replace_fun_symbol(fun_symbol);
        thunk
    }

    fn append_text(&mut self, text: &[u8]) {
        self.text.borrow_mut().content.extend_from_slice(text);
        self.text.borrow_mut().header.sh_size += text.len() as u64;
        self.generated_fun_symbol.borrow_mut().sym.st_size += text.len() as u64;
    }

    fn prepend_text(&mut self, text: &[u8]) {
        self.text
            .borrow_mut()
            .content
            .splice(0..0, text.iter().cloned());

        self.text.borrow_mut().header.sh_size += text.len() as u64;

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
        symbols: vec![func64_symbol, section_symbol],
    }
}

fn create_st_info(bind: u8, symbol_type: u8) -> u8 {
    (bind << 4) + (symbol_type & 0xf)
}
