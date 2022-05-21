#include <stdio.h>

#include "authenticator.h"
#include "relying-party.h"

#include "mbedtls/md.h"
#include "mbedtls/hkdf.h"

// Registration

// Main

void registration()
{
    // Relying Party creates and sends DH Part 1
    uint8_t dhPart1[256] = {0};
    uint8_t privKeyRP[32] = {0};
    size_t dhPart1Size = rp_registration_create_dh_extension(privKeyRP, dhPart1, sizeof(dhPart1));
    printf("Registration input extension - \"dh\": ");
    printBufferToHex(stdout, dhPart1, dhPart1Size);

    // Authenticator receives DH Part 1, creates DH Part 2 and computes a shared key
    uint8_t pubKeyAU[64] = {0};
    uint8_t sharedSecretAU[32] = {0};
    uint8_t sharedKeyAU[16] = {0};
    au_registration_process_dh_extension(dhPart1, dhPart1Size, sharedSecretAU, pubKeyAU);
    
    // Authenticator derives key material from shared secret
    mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0, sharedSecretAU, sizeof(sharedSecretAU), NULL, 0, sharedKeyAU, sizeof(sharedKeyAU));
    printf("Shared key Authenticator: ");
    printBufferToHex(stdout, sharedKeyAU, sizeof(sharedKeyAU));

    // Authenticator sends DH Part 2
    uint8_t dhPart2[256] = {0};
    size_t dhPart2Size = au_registration_create_dh_extension(pubKeyAU, dhPart2, sizeof(dhPart2));
    printf("\nRegistration output extension - \"dh\": ");
    printBufferToHex(stdout, dhPart2, dhPart2Size);

    // Relying Party computes the same shared key from DH Part 1 and DH Part 2
    uint8_t sharedSecretRP[32] = {0};
    uint8_t sharedKeyRP[16] = {0};
    rp_registration_process_dh_extension(dhPart2, dhPart2Size, privKeyRP, sharedSecretRP);
   
    // Relying Party derives key material from shared secret
    mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0, sharedSecretRP, sizeof(sharedSecretRP), NULL, 0, sharedKeyRP, sizeof(sharedKeyRP));
    printf("Shared key Relying Party: ");
    printBufferToHex(stdout, sharedKeyRP, sizeof(sharedKeyRP));
}

void assertion()
{
    // Known by Authenticator and Relying Party
    uint8_t credentialId[16];
    generateRandomBytes(credentialId, sizeof(credentialId));
    uint8_t sharedKey[16];
    generateRandomBytes(sharedKey, sizeof(sharedKey));
    
    // Relying party creates and sends encypted input extensions
    const char *inputExtensions = "<Secret input extensions>";
    uint8_t protectedInputExtensions[256];
    size_t protectedInputExtensionsSize = rp_assertion_create_protected_extension(inputExtensions, strlen(inputExtensions) + 1, credentialId, sharedKey, protectedInputExtensions, sizeof(protectedInputExtensions));
    printf("Assertion input extension - \"protected\": ");
    printBufferToHex(stdout, protectedInputExtensions, protectedInputExtensionsSize);

    // Authenticator decrypts input extensions
    uint8_t receivedInputExtensions[128];
    size_t receivedInputExtensionsSize = au_assertion_process_protected_extension(protectedInputExtensions, protectedInputExtensionsSize, credentialId, sharedKey, receivedInputExtensions, sizeof(receivedInputExtensions));
    if (receivedInputExtensionsSize > 0)
    {
        printf("Received input extensions: %s\n", receivedInputExtensions);
    }

    // Authenticator creates and sends encrypted output extensions
    const char *outputExtensions = "<Secret output extensions>";
    uint8_t protectedOutputExtensions[256];
    size_t protectedOutputExtensionsSize = au_assertion_create_protected_extension(outputExtensions, strlen(outputExtensions) + 1, credentialId, sharedKey, protectedOutputExtensions, sizeof(protectedOutputExtensions));
    printf("\nAssertion output extension - \"protected\": ");
    printBufferToHex(stdout, protectedOutputExtensions, protectedOutputExtensionsSize);

    // Relying party decrypts output extensions
    uint8_t receivedOutputExtensions[128];
    size_t receivedOutputExtensionsSize = rp_assertion_process_protected_extension(protectedOutputExtensions, protectedOutputExtensionsSize, sharedKey, receivedOutputExtensions, sizeof(receivedOutputExtensions));
    if (receivedOutputExtensionsSize > 0)
    {
        printf("Received input extensions: %s\n", receivedOutputExtensions);
    }
}

int main()
{
    /* Registration */
    registration();

    printf("\n");

    /* Assertion */
    assertion();

    return 0;
}