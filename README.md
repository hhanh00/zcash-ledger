## Disclaimer

This project is under development but is working AFAIK. Please
report any issue you find.

It is supported by a grant from the Zcash community and will
be submitted to Ledger for official inclusion in their app store.

The submission has not been filed yet.

> Use at your own risk

I highly recommend using a dedicated Ledger device 
though Ledger OS security isolates coins from each other.

## Security

**This application is locked to the Zcash derivation path and
cannot access other coins**

## Supported Devices

> Only the Ledger Nano S+ is supported

- Nano S does not have enough RAM. It is no longer on sale too.
- Nano X does not support side-loading
- Nano Stax is not available to the public yet

## Installation

- Install python
- Install [ledgerblue](https://github.com/LedgerHQ/blue-loader-python)
- Download and unzip the release
- Run the install script `install.sh` or the command below

```
python3 -m ledgerblue.loadApp --curve secp256k1 --appFlags 0x000 --path "44'/133'" --tlv --targetId 0x33100004 --apiLevel 1 --delete --fileName bin/app.hex --appName "Zcash" --appVersion "1.0.1" --dataSize 0 
```
