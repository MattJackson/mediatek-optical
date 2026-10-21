//! Compiled host integration example. Running this example does not access a drive.
use mediatek_optical::{
    drive::{self, Transport},
    envelope::Envelope,
    receiver,
    update::{Completion, FlashRuntime, FlashTransport, InstalledFirmware},
};

/// Execute after the host has backed up the drive, obtained consent and ensured
/// both transports address that same physical drive exclusively.
pub fn flash<R, W, H>(
    reads: &mut R,
    writes: &mut W,
    runtime: &mut H,
    current_image: &[u8],
    target_image: &[u8],
) -> Result<Completion, Box<dyn std::error::Error>>
where
    R: Transport<Error = W::Error>,
    W: Transport,
    W::Error: 'static,
    H: FlashRuntime<W::Error>,
{
    let identity = drive::identify(reads)?;
    let installed = InstalledFirmware::new(identity, current_image)?;
    let mode = receiver::detect_mode(reads)?;
    let receiver = receiver::detect(reads, &mode)?;
    let target = Envelope::load(target_image)?;
    let prepared = receiver.prepare(&target, &installed)?;
    Ok(prepared.flash_completed(FlashTransport { reads, writes }, runtime)?)
}

fn main() {
    println!("Implement Transport and FlashRuntime, then call flash with captured firmware.");
}
