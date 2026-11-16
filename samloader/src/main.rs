// Copyright 2026 John "topjohnwu" Wu
// Copyright 2021-2024 Henrik Grimler
// Copyright 2010-2017 Benjamin Dobell, Glass Echidna
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[cfg(not(any(feature = "rusb", feature = "nusb", feature = "serialport")))]
compile_error!("At least one USB backend must be enabled!");

mod cli;
mod commands;
mod progress;
mod readahead;

use clap::Parser;
use cli::{Cli, Command};
use commands::AlreadyReported;

#[macro_export]
macro_rules! print_error {
    ($($arg:tt)*) => {
        eprint!("ERROR: ");
        eprintln!($($arg)*);
    };
}

#[cfg(any(target_os = "linux", test))]
fn has_device_access_error(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = current {
        if matches!(
            e.downcast_ref::<samloader_odin::TransportError>(),
            Some(samloader_odin::TransportError::DeviceAccess(_))
        ) {
            return true;
        }
        current = e.source();
    }
    false
}

fn main() {
    let Cli {
        verbose,
        usb_backend,
        command,
    } = Cli::parse();

    let result = match command {
        Command::Download(args) => commands::download::run(args, verbose),
        Command::CheckUpdate(args) => commands::check_update::run(args),
        Command::Detect(args) => commands::detect::run(args, usb_backend),
        Command::DumpPit(args) => commands::pit::dump(args, usb_backend, verbose),
        Command::PrintPit(args) => commands::pit::print(args, usb_backend, verbose),
        Command::Flash(args) => commands::flash::run(args, usb_backend, verbose),
        Command::VerifyMd5(args) => commands::md5::run(args),
        Command::RebootDownload => commands::reboot::run(usb_backend, verbose),
        #[cfg(target_os = "linux")]
        Command::FixUsb => commands::fix_usb::run(),
    };

    if let Err(e) = result {
        if !e.is::<AlreadyReported>() {
            print_error!("{}", e);
            #[cfg(target_os = "linux")]
            if has_device_access_error(&*e) {
                eprintln!(
                    "\nOn Linux, this is usually because your user lacks write permission to the USB device node.\n\
                     To automatically fix this, please run the builtin fix command as root:\n\n\
                     \tsudo samloader fix-usb"
                );
            }
        }
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use samloader_odin::{FlashError, OdinError, TransportError};
    use std::error::Error;
    use std::io::{Error as IoError, ErrorKind};

    #[test]
    fn test_has_device_access_error_in_chain() {
        let access =
            || TransportError::DeviceAccess(Box::new(IoError::from(ErrorKind::PermissionDenied)));

        let direct: Box<dyn Error> = Box::new(access());
        assert!(has_device_access_error(&*direct));

        let wrapped_odin: Box<dyn Error> = Box::new(OdinError::from(access()));
        assert!(has_device_access_error(&*wrapped_odin));

        let wrapped_flash: Box<dyn Error> = Box::new(FlashError::from(OdinError::from(access())));
        assert!(has_device_access_error(&*wrapped_flash));

        let timeout: Box<dyn Error> = Box::new(OdinError::from(TransportError::Timeout));
        assert!(!has_device_access_error(&*timeout));
    }
}
