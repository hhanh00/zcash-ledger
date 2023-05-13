## Disclaimer

It is supported by a [grant from the Zcash community](https://zcashgrants.org/gallery/25215916-53ea-4041-a3b2-6d00c487917d/35722316/).

It was submitted to Ledger for review. Once it is approved,
it will be available on the Ledger App Store.

## Security

**This application is locked to the Zcash derivation path and
cannot access other coins**

## Supported Devices

> Only the Ledger Nano S+ is supported

- Nano S does not have enough RAM. It is no longer on sale too.
- Nano X does not support side-loading
- Nano Stax is not available to the public yet

## Installation (SIDE LOADING)

You can install the app on a Nano S+ via sideloading. 

- Install python
- Install [ledgerblue](https://github.com/LedgerHQ/blue-loader-python)
- Download and unzip the release
- Run the install script `install.sh` or the command below

```
python3 -m ledgerblue.loadApp --curve secp256k1 --appFlags 0x000 --path "44'/133'" --tlv --targetId 0x33100004 --apiLevel 1 --delete --fileName bin/app.hex --appName "Zcash" --appVersion "1.0.1" --dataSize 0 
```
or
```
python3 -m ledgerblue.runScript --scp --fileName bin/app.apdu --elfFile bin/app.elf
```

## YWallet 

[YWallet documentation](https://ywallet.app/advanced/ledger/)
