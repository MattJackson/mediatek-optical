use super::{validate, Protocol};

const SOURCE_CELL: u32 = 0x0200_0200;
const LENGTH_CELL: u32 = 0x0200_0210;
const READY_CELL: u32 = 0x0200_020c;

/// Native committer shape: publish the source address, normalize the length
/// cell in place (+16), reload it and write it to the DMA length register.
fn committer(gap: u16) -> Vec<u8> {
    let halfwords: [u16; 28] = [
        0x490d, 0xb510, 0x680a,
        0x4c0d, // ldr r1,=source; push {r4,lr}; ldr r2,[r1]; ldr r4,=dma
        0x1810, 0x62a0, 0x480c, gap, // add r0,r2,r0; str r0,[r4,#40]; ldr r0,=length; <gap>
        0x8801, 0x4b0c, 0x4299, 0xd102, // +16: ldrh r1,[r0]; ldr r3,=0xffff; cmp; bne +30
        0x8801, 0x1e49, 0x8001, // ldrh; sub r1,r1,#1; strh
        0x8801, 0x07c9, 0xd002, // +30: ldrh; lsl r1,r1,#31; beq +42
        0x8801, 0x1c49, 0x8001, // ldrh; add r1,r1,#1; strh
        0x8801, 0x4806, 0x6141, // +42: ldrh r1,[r0]; ldr r0,=0x04042140; str r1,[r0,#20]
        0x4906, 0x2001, 0x7008, 0xbd10, // ldr r1,=ready; mov r0,#1; strb r0,[r1]; pop {r4,pc}
    ];
    let mut image: Vec<u8> = halfwords.iter().flat_map(|h| h.to_le_bytes()).collect();
    for word in [
        SOURCE_CELL,
        0x0403_00c0,
        LENGTH_CELL,
        0xffff,
        0x0404_2140,
        READY_CELL,
    ] {
        image.extend(word.to_le_bytes());
    }
    image
}

#[test]
fn committer_fixture_matches_native_protocol() {
    let protocol = validate(&committer(0xbf00), 0, SOURCE_CELL, LENGTH_CELL);
    assert_eq!(
        protocol,
        Ok(Protocol {
            length_writes: vec![46],
            ready_cell: READY_CELL,
            returns: vec![54],
        })
    );
}

#[test]
fn length_write_requires_normalization_on_its_path() {
    // `b +42` skips the intact normalization block, so the raw (odd or 0xffff)
    // length reaches the DMA length register.
    let image = committer(0xe00c);
    assert_eq!(
        validate(&image, 0, SOURCE_CELL, LENGTH_CELL),
        Err(super::Error::InvalidContract)
    );
}

#[test]
fn length_loaded_before_normalization_is_stale() {
    // `ldrh r2,[length]` before the block, then `str r2` to the DMA register:
    // the normalization ran on the path, but r2 still holds the raw length.
    let mut image = committer(0x8802);
    image[46..48].copy_from_slice(&0x6142u16.to_le_bytes());
    assert_eq!(
        validate(&image, 0, SOURCE_CELL, LENGTH_CELL),
        Err(super::Error::InvalidContract)
    );
}
