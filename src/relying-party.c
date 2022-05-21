#include "relying-party.h"

#include "uECC.h"
#include "mbedtls/md.h"
#include "mbedtls/hkdf.h"

#include "cose.h"
#include "cose-key.h"
#include "cose-encrypt.h"

// Registration
size_t rp_registration_create_dh_extension(uint8_t outPrivKey[32], uint8_t *outBuf, size_t outBufSize)
{
    // Generate EC key pair
    uint8_t pubKey[64] = {0};
    if (!uECC_make_key(pubKey, outPrivKey, uECC_secp256r1()))
        return 0;

    // Encode public key to COSE Key to be send to AU
    COSE_Key coseKeyRp;
    cose_init_key(&coseKeyRp);
    coseKeyRp.kty = COSE_KEY_TYPE_EC2;
    coseKeyRp.alg = -7;
    coseKeyRp.crv = 1;
    memmove(coseKeyRp.x, pubKey, 32);
    coseKeyRp.xSize = 32;
    memmove(coseKeyRp.y, &pubKey[32], 32);
    coseKeyRp.ySize = 32;
    return cose_encode_key(&coseKeyRp, outBuf, outBufSize);
}

int rp_registration_process_dh_extension(uint8_t *data, size_t dataSize, uint8_t inPrivKey[32], uint8_t sharedSecret[32])
{
    // Decode COSE Key from AU
    COSE_Key coseKeyAu;
    cose_init_key(&coseKeyAu);
    cose_decode_key(data, dataSize, &coseKeyAu);
    uint8_t pubKeyAu[coseKeyAu.xSize + coseKeyAu.ySize];
    memmove(pubKeyAu, coseKeyAu.x, coseKeyAu.xSize);
    memmove(&pubKeyAu[coseKeyAu.xSize], coseKeyAu.y, coseKeyAu.ySize);

    // Compute shared secret
    return uECC_shared_secret(pubKeyAu, inPrivKey, sharedSecret, uECC_secp256r1());
}

// Assertion
size_t rp_assertion_create_protected_extension(uint8_t *extensions, size_t extensionsSize, uint8_t credId[16], uint8_t sharedKey[16], uint8_t *outBuf, size_t outBufSize)
{
    // Create COSE Recipients
    int numRecipients = 1;
    COSE_Key receiverKeys[numRecipients];
    cose_init_key(&receiverKeys[0]);
    receiverKeys[0].kty = COSE_KEY_TYPE_Symmetric;
    receiverKeys[0].alg = COSE_ENCRYPT_ALG_A128GCM;
    memcpy(receiverKeys[0].kid, credId, 16);
    receiverKeys[0].kidSize = 16;
    memcpy(receiverKeys[0].k, sharedKey, 16);
    receiverKeys[0].kSize = 16;

    // Encrypt message
    COSE_Message coseMsg;
    cose_encrypt_encrypt(COSE_ENCRYPT_ALG_A128GCM, extensions, extensionsSize, receiverKeys, 1, &coseMsg);
    return cose_encode_message(coseMsg, outBuf, outBufSize);
}

size_t rp_assertion_process_protected_extension(uint8_t *data, size_t dataSize, uint8_t sharedKey[16], uint8_t *outBuf, size_t outBufSize)
{
    // Decode COSE Encrypt0 message from AU
    COSE_Message coseMsg;
    cose_decode_message(data, dataSize, &coseMsg);
    uint8_t plain[128] = {0};
    return cose_encrypt0_decrypt(&coseMsg, sharedKey, 16, outBuf, outBufSize);
}