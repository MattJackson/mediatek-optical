//! Compiled host integration example. Running this example does not access a drive.
use mediatek_optical::{
    classify::InstalledFirmware,
    drive::{self, ExecutionRuntime, FlashOutcome, FlashTransport, Transport},
    envelope::Envelope,
};

/// Execute after the host has backed up the drive, obtained consent and ensured
/// both transports address that same physical drive exclusively.
pub fn flash<R, W, H>(
    reads: &mut R,
    writes: &mut W,
    runtime: &mut H,
    current_image: &[u8],
    target_image: &[u8],
) -> Result<FlashOutcome, Box<dyn std::error::Error>>
where
    R: Transport<Error = W::Error>,
    W: Transport,
    W::Error: 'static,
    H: ExecutionRuntime<W::Error>,
{
    let identity = drive::identify(reads)?;
    let installed = InstalledFirmware::new(identity, current_image)?;
    let receiver = drive::detect_receiver(reads)?;
    let target = Envelope::load(target_image)?;
    let prepared = receiver.prepare(&target, &installed)?;
    // Report `readback` quality and `startup.evidence()`: `Unobserved` is not
    // confirmed startup; advise a power cycle and re-identification.
    Ok(prepared.flash_completed(FlashTransport { reads, writes }, runtime)?)
}

fn main() {
    println!("Implement Transport and ExecutionRuntime, then call flash with captured firmware.");
}
