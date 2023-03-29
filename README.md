# Ledger Boilerplate Application

This is a boilerplate application which can be forked to start a new project for the Ledger Nano S/X.

## Prerequisite

### With the docker image builder

The app-builder docker image [from this repository](https://github.com/LedgerHQ/ledger-app-builder) contains all needed tools and library to build and load an application.
You can download it from the ghcr.io docker repository:

```shell
sudo docker pull ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-full
```

You can then enter this development environment by executing the following command from the directory of the application `git` repository:

```shell
sudo docker run --rm -ti --user "$(id -u)":"$(id -g)" -v "$(realpath .):/app" ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-full
```

The application's code will be available from inside the docker container, you can proceed to the following compilation steps to build your app.

### Without the docker image builder

Be sure to have your environment correctly set up (see [Getting Started](https://developers.ledger.com/docs/nano-app/introduction/)) and [ledgerblue](https://pypi.org/project/ledgerblue/) and installed.

If you want to benefit from [vscode](https://code.visualstudio.com/) integration, it's recommended to move the toolchain in `/opt` and set `BOLOS_ENV` environment variable as follows

```shell
BOLOS_ENV=/opt/bolos-devenv
```

and do the same with `BOLOS_SDK` environment variable

```shell
BOLOS_SDK=/opt/nanos-secure-sdk
```

## Compilation and load

```shell
make DEBUG=1  # compile optionally with PRINTF
make load     # load the app on the Nano using ledgerblue
```

