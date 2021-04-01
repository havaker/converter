use goblin::elf::{self, section_header::*};
use std::{collections::HashMap, ffi::CString};

use super::Section;

#[derive(Debug, Clone)]
pub struct Strtab {
    strings: Vec<String>,
    offsets: HashMap<String, usize>,
}

impl Strtab {
    pub fn new(iter: impl Iterator<Item = String>) -> Self {
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

    pub fn offset_for_string(&self, string: &str) -> Option<usize> {
        self.offsets.get(string).cloned()
    }

    pub fn to_section(&self, name: String) -> Section {
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
