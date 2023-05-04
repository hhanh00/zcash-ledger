# Crypto systems

Zcash includes three distinct crypto systems:
- the transparent pool uses Bitcoin crypto,
- the sapling pool uses Jubjub and Groth16 proving system
- the orchard pool uses Pallas/Vesta and the Halo2 proving system.

The Bitcoin crypto primitives are part of the BOLOS.
The other two are not available and have to be implemented
in software.

The following table describes the various parts of the implementation.

| Functionality | Sapling | Orchard |
| --- | --- | --- |
| Hash | Blake2b | Blake 2b |
| Base Field | Fq | Fp |
| Scalar Field | Fr | Fv | 
| Curve Type | Edward Twisted | Montgomerry |
| Curve Name | Jubjub | Pallas |
| Affine Coordinates | u,v | x,y |
| Extended Coordinates | Extended, Extended Niels | Jacobian |
| Scalar Point Multiplication | Double and Add | Double and Add |
| Point Compression | v + sign u | y + sign x |
| Hash to Point | u (incomplete) | SWSU + Isogenies |
| Commitment | Pedersen | Sinsemilla |
| Diversifier | FF1 | FF1 | 
| Address Encoding | Bech32M | F4Jumble, Bech32M |

For performance reasons, the Double and Add part uses Montgomerry Multiplication
on the actual devices. The emulator does not support MM at the moment.
