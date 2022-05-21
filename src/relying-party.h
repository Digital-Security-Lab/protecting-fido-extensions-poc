#ifndef RELYING_PARTY_H
#define RELYING_PARTY_H

#include <stdint.h>
#include <stddef.h>

// Registration
size_t rp_registration_create_dh_extension(uint8_t outPrivKey[32], uint8_t *outBuf, size_t outBufSize);
int rp_registration_process_dh_extension(uint8_t *data, size_t dataSize, uint8_t inPrivKey[32], uint8_t sharedSecret[32]);

// Assertion
size_t rp_assertion_create_protected_extension(uint8_t *extensions, size_t extensionsSize, uint8_t credId[16], uint8_t sharedKey[16], uint8_t *outBuf, size_t outBufSize);
size_t rp_assertion_process_protected_extension(uint8_t *data, size_t dataSize, uint8_t sharedKey[16], uint8_t *outBuf, size_t outBufSize);

#endif