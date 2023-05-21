## Disclaimer

It is supported by a [grant from the Zcash community](https://zcashgrants.org/gallery/25215916-53ea-4041-a3b2-6d00c487917d/35722316/).

It was submitted to Ledger for review. Once it is approved,
it will be available on the Ledger App Store.

## Security

**This application is locked to the Zcash derivation path and
cannot access other coins**

## Supported Devices

- Nano S does not have enough RAM for Orchard. You can use Transparent and Sapling
- Nano S+ supports every pool
- Nano X does not support side-loading. You need to wait until Ledger publishes the app on Ledger Live
- Nano Stax is not supported

## Installation (SIDE LOADING)

You can install the app on a Nano S/S+ via sideloading. 

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

## Windows

- Install [python 3.11](https://www.python.org/ftp/python/3.11.3/python-3.11.3-amd64.exe)
Don't forget to check **Add Python to the PATH**
- Download and uncompress either `nanos.zip` or `nanosplus.zip` depending on the model of your Ledger
- Open a Command Shell in that directory. It should have `bin` and `debug` subdirectories
- Connect your Nano to your computer via USB and enter the PIN to unlock it
- Run
```
pip install ledgerblue
python -m ledgerblue.runScript --scp --fileName bin/app.apdu --elfFile bin/app.elf
```

You should get something like this (with different numbers):
```
Generated random root public key : b'0419096b005c48721611e043315514c6f296444a66c807f38f226a524929dbce8c024dee652fbb0a6e50d52a24d5608fb3ab02780240f22bccf689c356778f8be2'
Using test master key b'0419096b005c48721611e043315514c6f296444a66c807f38f226a524929dbce8c024dee652fbb0a6e50d52a24d5608fb3ab02780240f22bccf689c356778f8be2' 
```

Your device will show "Deny unsafe manager". Press the right button several times until you get "Allow unsafe manager", then validate by pressing both buttons.
The app will get uploaded to your device and it will display "Install app Zcash".
Press the right button several time until you reach the "Perform installation" option and validate with both buttons.
You will be asked to enter your PIN. After that, the installation is complete and the Zcash
application is on your Ledger main menu.

When you launch the app, you will be notified that it is not a genuine app, because it isn't
signed by Ledger. It is expected since you are sideloading it. 
Press the right button several times until you get "Open application" and validate by pressing both buttons.

The application identifier is the SHA-256 of the binary and is stored in the file `app.sha256`.
You can check it to make sure the app is correctly loaded.

## YWallet 

[YWallet documentation](https://ywallet.app/advanced/ledger/)

## Performance

| Action | Duration |
|---|---|
| Sapling Key Derivation | 0:30 |
| Orchard Key Derivation | 1:30 |
| Sapling Output | 1:15 |
| Sapling Input | 0:30 |
| Orchard Action | 1:15 + 0:15 |

Keys are derived once per session, i.e. execution of the Zcash app. The first transaction will
take an extra 2 mn during which keys are calculated. Afterward, they are kept in memory until
the app is closed or the device unplugged. One useful trick is to use the "Get UA" menu to trigger
key derivation while you are preparing the transaction.

Example A: **1 sapling input, 2 sapling outputs** will take 2x1:15 + 0:30 = **3 minutes**

Example B: **1 orchard input, 2 orchard outputs**. Orchard counts in "actions". An action combines
an input and an output. This transaction requires 2 actions (with 1 dummy input).
It will take 2x(1:15+0:15) = 2x1:30 = **3 minutes**. Even though signing is faster with Orchard,
in this case we had to sign a dummy spend, therefore the duration was the same as the previous
example.

The signing algorithms run in constant time in order to avoid side channel attacks.
