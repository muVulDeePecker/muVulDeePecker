/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE321_Hard_Coded_Cryptographic_Key__w32_char_67b.c
Label Definition File: CWE321_Hard_Coded_Cryptographic_Key__w32.label.xml
Template File: sources-sink-67b.tmpl.c
*/
/*
 * @description
 * CWE: 321 Use of Hard-coded Cryptographic Key
 * BadSource:  Copy a hardcoded value into cryptoKey
 * GoodSource: Read cryptoKey from the console
 * Sinks:
 *    BadSink : Hash cryptoKey and use the value to encrypt a string
 * Flow Variant: 67 Data flow: data passed in a struct from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#define CRYPTO_KEY "Hardcoded"

#include <windows.h>
#include <wincrypt.h>

/* Link with the Advapi32.lib file for Crypt* functions */
#pragma comment (lib, "Advapi32")

typedef struct _CWE321_Hard_Coded_Cryptographic_Key__w32_char_67_structType
{
    char * structFirst;
} CWE321_Hard_Coded_Cryptographic_Key__w32_char_67_structType;

#ifndef OMITBAD

void CWE321_Hard_Coded_Cryptographic_Key__w32_char_67b_badSink(CWE321_Hard_Coded_Cryptographic_Key__w32_char_67_structType myStruct)
{
    char * cryptoKey = myStruct.structFirst;
    {
        HCRYPTPROV hCryptProv;
        HCRYPTKEY hKey;
        HCRYPTHASH hHash;
        char toBeEncrypted[] = "String to be encrypted";
        DWORD encryptedLen = strlen(toBeEncrypted)*sizeof(char);
        BYTE encrypted[200];    /* buffer should be larger than toBeEncrypted to have room for IV and padding */
        /* Copy plaintext (without NUL terminator) into byte buffer */
        memcpy(encrypted, toBeEncrypted, encryptedLen);
        /* Try to get a context with and without a new key set */
        if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_AES, 0))
        {
            if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_AES, CRYPT_NEWKEYSET))
            {
                printLine("Error in acquiring cryptographic context");
                exit(1);
            }
        }
        /* Create Hash handle */
        if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash))
        {
            printLine("Error in creating hash");
            exit(1);
        }
        /* Hash the cryptoKey */
        if(!CryptHashData(hHash, (BYTE *) cryptoKey, strlen(cryptoKey)*sizeof(char), 0))
        {
            printLine("Error in hashing cryptoKey");
            exit(1);
        }
        /* Derive an AES key from the Hashed cryptoKey */
        if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey))
        {
            printLine("Error in CryptDeriveKey");
            exit(1);
        }
        /* POTENTIAL FLAW: Possibly using a hardcoded crypto key */
        /* Use the derived key to encrypt something */
        if(!CryptEncrypt(hKey, (HCRYPTHASH)NULL, 1, 0, encrypted, &encryptedLen, sizeof(encrypted)))
        {
            printLine("Error in CryptEncrypt");
            exit(1);
        }
        /* use encrypted block */
        printBytesLine(encrypted, encryptedLen);
        if (hKey)
        {
            CryptDestroyKey(hKey);
        }
        if (hHash)
        {
            CryptDestroyHash(hHash);
        }
        if (hCryptProv)
        {
            CryptReleaseContext(hCryptProv, 0);
        }
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE321_Hard_Coded_Cryptographic_Key__w32_char_67b_goodG2BSink(CWE321_Hard_Coded_Cryptographic_Key__w32_char_67_structType myStruct)
{
    char * cryptoKey = myStruct.structFirst;
    {
        HCRYPTPROV hCryptProv;
        HCRYPTKEY hKey;
        HCRYPTHASH hHash;
        char toBeEncrypted[] = "String to be encrypted";
        DWORD encryptedLen = strlen(toBeEncrypted)*sizeof(char);
        BYTE encrypted[200];    /* buffer should be larger than toBeEncrypted to have room for IV and padding */
        /* Copy plaintext (without NUL terminator) into byte buffer */
        memcpy(encrypted, toBeEncrypted, encryptedLen);
        /* Try to get a context with and without a new key set */
        if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_AES, 0))
        {
            if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_AES, CRYPT_NEWKEYSET))
            {
                printLine("Error in acquiring cryptographic context");
                exit(1);
            }
        }
        /* Create Hash handle */
        if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash))
        {
            printLine("Error in creating hash");
            exit(1);
        }
        /* Hash the cryptoKey */
        if(!CryptHashData(hHash, (BYTE *) cryptoKey, strlen(cryptoKey)*sizeof(char), 0))
        {
            printLine("Error in hashing cryptoKey");
            exit(1);
        }
        /* Derive an AES key from the Hashed cryptoKey */
        if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey))
        {
            printLine("Error in CryptDeriveKey");
            exit(1);
        }
        /* POTENTIAL FLAW: Possibly using a hardcoded crypto key */
        /* Use the derived key to encrypt something */
        if(!CryptEncrypt(hKey, (HCRYPTHASH)NULL, 1, 0, encrypted, &encryptedLen, sizeof(encrypted)))
        {
            printLine("Error in CryptEncrypt");
            exit(1);
        }
        /* use encrypted block */
        printBytesLine(encrypted, encryptedLen);
        if (hKey)
        {
            CryptDestroyKey(hKey);
        }
        if (hHash)
        {
            CryptDestroyHash(hHash);
        }
        if (hCryptProv)
        {
            CryptReleaseContext(hCryptProv, 0);
        }
    }
}

#endif /* OMITGOOD */
