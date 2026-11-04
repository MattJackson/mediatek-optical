use super::*;

#[test]
fn compiler_trampolines_are_bounded_and_cycles_are_rejected() {
    // Three forward branches followed by a buffer-id load.
    let bytes = [
        0x00, 0xe0, 0xff, 0xff, 0x00, 0xe0, 0xff, 0xff, 0x00, 0xe0, 0xff, 0xff, 0x83, 0x78,
    ];
    assert_eq!(
        follow(
            &Window {
                bytes: &bytes,
                base: 0x1000
            },
            0x1000
        ),
        Some(0x100c)
    );
    // A fourth trampoline whose destination is an in-window non-branch:
    // only the three-step bound rejects it.
    let mut fourth = [0xff; 18];
    fourth[..12].copy_from_slice(&bytes[..12]);
    fourth[12..14].copy_from_slice(&[0x00, 0xe0]);
    fourth[16..18].copy_from_slice(&[0x83, 0x78]);
    assert_eq!(
        follow(
            &Window {
                bytes: &fourth,
                base: 0x1000
            },
            0x1000
        ),
        None
    );
    // With a three-step bound any cycle also ends at a branch, so this only
    // pins the observable result; the explicit cycle check is not separable.
    let cycle = [0xfe, 0xe7];
    assert_eq!(
        follow(
            &Window {
                bytes: &cycle,
                base: 0x1000
            },
            0x1000
        ),
        None
    );
    assert_eq!(
        follow(
            &Window {
                bytes: &bytes[..1],
                base: 0x1000
            },
            0x1000
        ),
        None
    );
}
