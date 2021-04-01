use goblin::{
    elf::{self, section_header::*},
    strtab,
};

#[derive(Debug, Clone)]
pub struct Section {
    // sh_name, sh_link and sh_info are invalid
    pub header: elf::SectionHeader,

    // for SHT_NOBITS section type, content.len() is 0 and header.sh_size >= 0
    pub content: Vec<u8>,

    // an object file can have more than one section with the same name.
    pub name: String,

    // computed during serialization process
    pub index: Option<usize>,
}

impl Section {
    pub fn extract(header: &SectionHeader, strtab: &strtab::Strtab, bytes: &Vec<u8>) -> Section {
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

    pub fn serialize(&self, buf: &mut Vec<u8>) -> usize {
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
