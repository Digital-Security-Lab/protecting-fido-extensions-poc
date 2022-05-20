# Protecting Fido Extensions - Proof of Concept
This repository contains a proof-of-concept implementation for a protocol to protect FIDO extensions.

## Dependencies
The following libraries are currently used and included as submodules:
* TinyCBOR https://github.com/intel/tinycbor
* Mbed TLS https://github.com/Mbed-TLS/mbedtls
* micro-ecc https://github.com/kmackay/micro-ecc
* cose-lib https://github.com/abuettner/cose-lib

## Build and run

### Getting the sources
```
git clone --recurse-submodules https://github.com/Digital-Security-Lab/protecting-fido-extensions-poc.git
```

### Compile
```
cd protecting-fido-extensions-poc
make all
```

### Run main
```
cd build
./main
```
