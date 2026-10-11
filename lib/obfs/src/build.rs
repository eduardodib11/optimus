//! Montagem de imagens OBFS (ferramentas de host, feature `alloc`).

use alloc::vec::Vec;

use super::{ALIGN, ENTRY_LEN, Error, HEADER_LEN, MAGIC, MAX_ENTRIES, NAME_LEN, VERSION, blake3};

/// Monta a imagem com `files` (nome e dados), na ordem dada.
///
/// # Errors
///
/// [`Error::BadCount`] sem arquivos ou com mais de [`MAX_ENTRIES`];
/// [`Error::BadName`] ou [`Error::DuplicateName`] para nomes recusados por
/// [`Image::parse`](super::Image::parse).
pub fn build(files: &[(&str, &[u8])]) -> Result<Vec<u8>, Error> {
    if files.is_empty() || files.len() > MAX_ENTRIES {
        return Err(Error::BadCount);
    }
    for (i, (name, _)) in files.iter().enumerate() {
        if !super::valid_name(name) {
            return Err(Error::BadName);
        }
        if files[..i].iter().any(|(other, _)| other == name) {
            return Err(Error::DuplicateName);
        }
    }
    let table_end = HEADER_LEN + files.len() * ENTRY_LEN;
    let data_offset = (table_end as u64).next_multiple_of(ALIGN);
    let mut image = alloc::vec![0; usize::try_from(data_offset).map_err(|_| Error::BadLayout)?];
    for (i, (name, data)) in files.iter().enumerate() {
        let offset = image.len() as u64;
        image.extend_from_slice(data);
        let padded = (image.len() as u64).next_multiple_of(ALIGN);
        image.resize(usize::try_from(padded).map_err(|_| Error::BadLayout)?, 0);
        let at = HEADER_LEN + i * ENTRY_LEN;
        let entry = &mut image[at..at + ENTRY_LEN];
        entry[..name.len().min(NAME_LEN)].copy_from_slice(name.as_bytes());
        entry[64..72].copy_from_slice(&offset.to_le_bytes());
        entry[72..80].copy_from_slice(&(data.len() as u64).to_le_bytes());
        entry[80..112].copy_from_slice(&blake3::hash(data));
    }
    let table_hash = blake3::hash(&image[HEADER_LEN..table_end]);
    let count = u32::try_from(files.len()).map_err(|_| Error::BadCount)?;
    let image_len = image.len() as u64;
    let header = &mut image[..HEADER_LEN];
    header[..4].copy_from_slice(&MAGIC);
    header[4..8].copy_from_slice(&VERSION.to_le_bytes());
    header[8..12].copy_from_slice(&count.to_le_bytes());
    header[16..24].copy_from_slice(&(HEADER_LEN as u64).to_le_bytes());
    header[24..32].copy_from_slice(&data_offset.to_le_bytes());
    header[32..40].copy_from_slice(&image_len.to_le_bytes());
    header[40..72].copy_from_slice(&table_hash);
    Ok(image)
}
