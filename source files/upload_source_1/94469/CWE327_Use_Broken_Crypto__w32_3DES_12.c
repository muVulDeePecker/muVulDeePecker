/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE327_Use_Broken_Crypto__w32_3DES_12.c
Label Definition File: CWE327_Use_Broken_Crypto__w32.label.xml
Template File: point-flaw-12.tmpl.c
*/
/*
 * @description
 * CWE: 327 Use of a Broken or Risky Cryptographic Algorithm
 * Sinks: 3DES
 *    GoodSink: Use AES for decryption
 *    BadSink : Use Triple DES for decryption
 * Flow Variant: 12 Control flow: if(globalReturnsTrueOrFalse())
 *
 * */

#include "std_testcase.h"

#include <windows.h>
#include <wincrypt.h>

/* Link with the Advapi32.lib file for Crypt* functions */
#pragma comment (lib, "Advapi32")

#ifndef OMITBAD

void CWE327_Use_Broken_Crypto__w32_3DES_12_bad()
{
    if(globalReturnsTrueOrFalse())
    {
        {
            FILE *pFile;
            HCRYPTPROV hCryptProv;
            HCRYPTKEY hKey;
            HCRYPTHASH hHash;
            char password[100];
            size_t passwordLen;
            char toBeDecrypted[100];
            DWORD toBeDecryptedLen = sizeof(toBeDecrypted)-1;
            /* Read the password from the console */
            printLine("Enter the password: ");
            if (fgets(password, 100, stdin) == NULL)
            {
                printLine("fgets() failed");
                /* Restore NUL terminator if fgets fails */
                password[0] = '\0';
            }
            /* The next 3 lines remove the carriage return from the string that is
             * inserted by fgets() */
            passwordLen = strlen(password);
            if (passwordLen > 0)
            {
                password[passwordLen-1] = '\0';
            }
            /* Read the data to be decrypted from a file */
            pFile = fopen("encrypted.txt", "rb");
            if (pFile == NULL)
            {
                exit(1);
            }
            if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100)
            {
                fclose(pFile);
                exit(1);
            }
            toBeDecrypted[99] = '\0';
            /* Try to get a context with and without a new key set */
            if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0))
            {
                if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_NEWKEYSET))
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
            /* Hash the password */
            if(!CryptHashData(hHash, (BYTE *) password, passwordLen, 0))
            {
                printLine("Error in hashing password");
                exit(1);
            }
            /* Derive a Triple DES key from the Hashed password */
            if(!CryptDeriveKey(hCryptProv, CALG_3DES, hHash, 0, &hKey))
            {
                printLine("Error in CryptDeriveKey");
                exit(1);
            }
            /* FLAW: Decrypt using Triple DES */
            if(!CryptDecrypt(hKey, 0, 1, 0, (BYTE *)toBeDecrypted, &toBeDecryptedLen))
            {
                printLine("Error in decryption");
                exit(1);
            }
            /* Ensure the plaintext is NUL-terminated */
            toBeDecrypted[toBeDecryptedLen] = '\0';
            printLine(toBeDecrypted);
            /* Cleanup */
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
            if (pFile)
            {
                fclose(pFile);
            }
        }
    }
    else
    {
        {
            FILE *pFile;
            HCRYPTPROV hCryptProv;
            HCRYPTKEY hKey;
            HCRYPTHASH hHash;
            char password[100];
            size_t passwordLen;
            char toBeDecrypted[100];
            DWORD toBeDecryptedLen = sizeof(toBeDecrypted)-1;
            /* Read the password from the console */
            printLine("Enter the password: ");
            if (fgets(password, 100, stdin) == NULL)
            {
                printLine("fgets() failed");
                /* Restore NUL terminator if fgets fails */
                password[0] = '\0';
            }
            /* The next 3 lines remove the carriage return from the string that is
             * inserted by fgets() */
            passwordLen = strlen(password);
            if (passwordLen > 0)
            {
                password[passwordLen-1] = '\0';
            }
            /* Read the data to be decrypted from a file */
            pFile = fopen("encrypted.txt", "rb");
            if (pFile == NULL)
            {
                exit(1);
            }
            if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100)
            {
                fclose(pFile);
                exit(1);
            }
            toBeDecrypted[99] = '\0';
            /* Try to get a context with and without a new key set */
            if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0))
            {
                if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_NEWKEYSET))
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
            /* Hash the password */
            if(!CryptHashData(hHash, (BYTE *) password, passwordLen, 0))
            {
                printLine("Error in hashing password");
                exit(1);
            }
            /* Derive an AES key from the Hashed password */
            if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey))
            {
                printLine("Error in CryptDeriveKey");
                exit(1);
            }
            /* FIX: Decrypt using AES */
            if(!CryptDecrypt(hKey, 0, 1, 0, (BYTE *)toBeDecrypted, &toBeDecryptedLen))
            {
                printLine("Error in decryption");
                exit(1);
            }
            /* Ensure the plaintext is NUL-terminated */
            toBeDecrypted[toBeDecryptedLen] = '\0';
            printLine(toBeDecrypted);
            /* Cleanup */
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
            if (pFile)
            {
                fclose(pFile);
            }
        }
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good1() uses the GoodSink on both sides of the "if" statement */
static void good1()
{
    if(globalReturnsTrueOrFalse())
    {
        {
            FILE *pFile;
            HCRYPTPROV hCryptProv;
            HCRYPTKEY hKey;
            HCRYPTHASH hHash;
            char password[100];
            size_t passwordLen;
            char toBeDecrypted[100];
            DWORD toBeDecryptedLen = sizeof(toBeDecrypted)-1;
            /* Read the password from the console */
            printLine("Enter the password: ");
            if (fgets(password, 100, stdin) == NULL)
            {
                printLine("fgets() failed");
                /* Restore NUL terminator if fgets fails */
                password[0] = '\0';
            }
            /* The next 3 lines remove the carriage return from the string that is
             * inserted by fgets() */
            passwordLen = strlen(password);
            if (passwordLen > 0)
            {
                password[passwordLen-1] = '\0';
            }
            /* Read the data to be decrypted from a file */
            pFile = fopen("encrypted.txt", "rb");
            if (pFile == NULL)
            {
                exit(1);
            }
            if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100)
            {
                fclose(pFile);
                exit(1);
            }
            toBeDecrypted[99] = '\0';
            /* Try to get a context with and without a new key set */
            if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0))
            {
                if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_NEWKEYSET))
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
            /* Hash the password */
            if(!CryptHashData(hHash, (BYTE *) password, passwordLen, 0))
            {
                printLine("Error in hashing password");
                exit(1);
            }
            /* Derive an AES key from the Hashed password */
            if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey))
            {
                printLine("Error in CryptDeriveKey");
                exit(1);
            }
            /* FIX: Decrypt using AES */
            if(!CryptDecrypt(hKey, 0, 1, 0, (BYTE *)toBeDecrypted, &toBeDecryptedLen))
            {
                printLine("Error in decryption");
                exit(1);
            }
            /* Ensure the plaintext is NUL-terminated */
            toBeDecrypted[toBeDecryptedLen] = '\0';
            printLine(toBeDecrypted);
            /* Cleanup */
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
            if (pFile)
            {
                fclose(pFile);
            }
        }
    }
    else
    {
        {
            FILE *pFile;
            HCRYPTPROV hCryptProv;
            HCRYPTKEY hKey;
            HCRYPTHASH hHash;
            char password[100];
            size_t passwordLen;
            char toBeDecrypted[100];
            DWORD toBeDecryptedLen = sizeof(toBeDecrypted)-1;
            /* Read the password from the console */
            printLine("Enter the password: ");
            if (fgets(password, 100, stdin) == NULL)
            {
                printLine("fgets() failed");
                /* Restore NUL terminator if fgets fails */
                password[0] = '\0';
            }
            /* The next 3 lines remove the carriage return from the string that is
             * inserted by fgets() */
            passwordLen = strlen(password);
            if (passwordLen > 0)
            {
                password[passwordLen-1] = '\0';
            }
            /* Read the data to be decrypted from a file */
            pFile = fopen("encrypted.txt", "rb");
            if (pFile == NULL)
            {
                exit(1);
            }
            if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100)
            {
                fclose(pFile);
                exit(1);
            }
            toBeDecrypted[99] = '\0';
            /* Try to get a context with and without a new key set */
            if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0))
            {
                if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_NEWKEYSET))
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
            /* Hash the password */
            if(!CryptHashData(hHash, (BYTE *) password, passwordLen, 0))
            {
                printLine("Error in hashing password");
                exit(1);
            }
            /* Derive an AES key from the Hashed password */
            if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey))
            {
                printLine("Error in CryptDeriveKey");
                exit(1);
            }
            /* FIX: Decrypt using AES */
            if(!CryptDecrypt(hKey, 0, 1, 0, (BYTE *)toBeDecrypted, &toBeDecryptedLen))
            {
                printLine("Error in decryption");
                exit(1);
            }
            /* Ensure the plaintext is NUL-terminated */
            toBeDecrypted[toBeDecryptedLen] = '\0';
            printLine(toBeDecrypted);
            /* Cleanup */
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
            if (pFile)
            {
                fclose(pFile);
            }
        }
    }
}

void CWE327_Use_Broken_Crypto__w32_3DES_12_good()
{
    good1();
}

#endif /* OMITGOOD */

/* Below is the main(). It is only used when building this testcase on
   its own for testing or for building a binary to use in testing binary
   analysis tools. It is not used when compiling all the testcases as one
   application, which is how source code analysis tools are tested. */

#ifdef INCLUDEMAIN

int main(int argc, char * argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
    printLine("Calling good()...");
    CWE327_Use_Broken_Crypto__w32_3DES_12_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE327_Use_Broken_Crypto__w32_3DES_12_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
