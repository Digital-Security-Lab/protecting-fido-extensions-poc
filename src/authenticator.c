#include "authenticator.h"


#include "uECC.h"

#include "cose.h"
#include "cose-key.h"
#include "cose-encrypt.h"

// Registration
int au_registration_process_dh_extension(uint8_t *data, size_t dataSize, uint8_t sharedSecret[32], uint8_t pubKey[64])
{
    // Decode COSE Key from RP
    COSE_Key coseKeyRp;
    cose_init_key(&coseKeyRp);
    cose_decode_key(data, dataSize, &coseKeyRp);
    uint8_t pubKeyRp[coseKeyRp.xSize + coseKeyRp.ySize];
    memmove(pubKeyRp, coseKeyRp.x, coseKeyRp.xSize);
    memmove(&pubKeyRp[coseKeyRp.xSize], coseKeyRp.y, coseKeyRp.ySize);

    // Generate EC key pair
    uint8_t privKey[32] = {0};
    if (!uECC_make_key(pubKey, privKey, uECC_secp256r1()))
        return 0;

    // Compute shared secret
    return uECC_shared_secret(pubKeyRp, privKey, sharedSecret, uECC_secp256r1());
}

size_t au_registration_create_dh_extension(uint8_t pubKey[64], uint8_t *outBuf, size_t outBufSize)
{
    // Encode public key to COSE Key to be send back to RP
    COSE_Key coseKeyAu;
    cose_init_key(&coseKeyAu);
    coseKeyAu.kty = COSE_KEY_TYPE_EC2;
    coseKeyAu.alg = -7;
    coseKeyAu.crv = 1;
    memmove(coseKeyAu.x, pubKey, 32);
    coseKeyAu.xSize = 32;
    memmove(coseKeyAu.y, &pubKey[32], 32);
    coseKeyAu.ySize = 32;
    return cose_encode_key(&coseKeyAu, outBuf, outBufSize);
}


// Assertion
size_t au_assertion_process_protected_extension(uint8_t *data, size_t dataSize, uint8_t credId[16], uint8_t sharedKey[16], uint8_t *outBuf, size_t outBufSize)
{
    // Create COSE Key struct with kid: credId and k: sharedKey
    COSE_Key coseKey;
    cose_init_key(&coseKey);
    coseKey.kty = COSE_KEY_TYPE_Symmetric;
    coseKey.alg = COSE_ENCRYPT_ALG_A128GCM;
    memcpy(coseKey.kid, credId, 16);
    coseKey.kidSize = 16;
    memcpy(coseKey.k, sharedKey, 16);
    coseKey.kSize = 16;

    // Decode COSE Encrypt message from RP
    COSE_Message coseMsg;
    cose_decode_message(data, dataSize, &coseMsg);

    // Decrypt message using the sharedKey
    return cose_encrypt_decrypt(&coseMsg, &coseKey, outBuf, outBufSize);
}

size_t au_assertion_create_protected_extension(uint8_t *extensions, size_t extensionsSize, uint8_t credId[16], uint8_t sharedKey[16], uint8_t *outBuf, size_t outBufSize)
{
    // Encrypt message using COSE Encrypt0
    COSE_Message coseMsg;
    cose_encrypt0_encrypt(COSE_ENCRYPT_ALG_A128GCM, extensions, extensionsSize, sharedKey, 16, credId, 16, &coseMsg);
    return cose_encode_message(coseMsg, outBuf, outBufSize);
}