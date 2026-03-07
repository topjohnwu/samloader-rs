# samloader-rs

Download firmware for Samsung devices from official Samsung servers.

```
Usage: samloader [OPTIONS] --model <MODEL> --region <REGION> <COMMAND>

Commands:
  download  Download the latest firmware
  check     Check the latest version
  help      Print this message or the help of the given subcommand(s)

Options:
  -m, --model <MODEL>      The model name (e.g. SM-S931U1)
  -r, --region <REGION>    Region CSC code (e.g. XAA)
  -i, --imei <IMEI>        IMEI number of the device, or an 8 digit TAC
  -s, --serial <SERIAL>    Serial number of the device
  -j, --threads <THREADS>  Number of parallel connections [default: 8]
  -h, --help               Print help
```

## Features

- Samsung server throttles the download speed per connection. This tool downloads the firmware with multiple connections (default: 8) to fully utilize your network bandwidth.
- Decryption happens on-the-fly. There are no separate download and decryption steps.

## Notes

This is not an officially supported Google product. This project is not
eligible for the [Google Open Source Software Vulnerability Rewards
Program](https://bughunters.google.com/open-source-security).

This project is based on `ananjaser1211/samloader` with assistance from Google Gemini for the initial Python to Rust conversion. Further development after the initial conversion are done by @topjohnwu.
