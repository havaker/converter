use goblin::elf::{
    self,
    reloc::{R_386_32, R_386_PC32, R_386_PLT32, R_X86_64_32, R_X86_64_PC32},
    section_header::*,
};
use std::{cell::RefCell, convert::TryInto, rc::Rc};

use super::{Section, Symbol, Symtab};

#[derive(Debug, Clone)]
pub struct Reloc {
    pub reloc: elf::Reloc,
    pub symbol: Rc<RefCell<Symbol>>,
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
        let addend = i32::from_le_bytes(addend_slice.as_ref().try_into().unwrap()) as i64;

        self.reloc.r_addend = Some(addend);
        for byte in addend_slice.iter_mut() {
            *byte = 0;
        }
    }
}

#[derive(Debug, Clone)]
pub struct RelocSection {
    pub target: Rc<RefCell<Section>>,
    pub relocs: Vec<Reloc>,
}

impl RelocSection {
    pub fn new(
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

    pub fn to_rela(&mut self) {
        for r in &mut self.relocs {
            r.update_to_rela(&mut self.target.borrow_mut());
        }
    }

    pub fn to_section(&self, symtab: &Section) -> Section {
        use goblin::container::{Container, Ctx, Endian};
        use scroll::Pwrite;

        let name = format!(".rela{}", self.target.borrow().name);
        // dbg!(&name);

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
