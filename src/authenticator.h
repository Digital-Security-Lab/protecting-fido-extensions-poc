#ifndef AUTHENTICATOR_H
#define AUTHENTICATOR_H

#include <stdint.h>
#include <stddef.h>

// Registration
int au_registration_process_dh_extension(uint8_t *data, size_t dataSize, uint8_t sharedSecret[32], uint8_t pubKey[64]);
size_t au_registration_create_dh_extension(uint8_t pubKey[64], uint8_t *outBuf, size_t outBufSize);


// Assertion
size_t au_assertion_process_protected_extension(uint8_t *data, size_t dataSize, uint8_t credId[16], uint8_t sharedKey[16], uint8_t *outBuf, size_t outBufSize);
size_t au_assertion_create_protected_extension(uint8_t *extensions, size_t extensionsSize, uint8_t credId[16], uint8_t sharedKey[16], uint8_t *outBuf, size_t outBufSize);

#endif