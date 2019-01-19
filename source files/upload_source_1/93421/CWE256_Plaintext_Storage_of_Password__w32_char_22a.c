/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE256_Plaintext_Storage_of_Password__w32_char_22a.c
Label Definition File: CWE256_Plaintext_Storage_of_Password__w32.label.xml
Template File: sources-sinks-22a.tmpl.c
*/
/*
 * @description
 * CWE: 256 Plaintext Storage of Password
 * BadSource:  Read the password from a file
 * GoodSource: Read the password from a file and decrypt it
 * Sinks:
 *    GoodSink: Decrypt the password then authenticate the user using LogonUserA()
 *    BadSink : Authenticate the user using LogonUserA()
 * Flow Variant: 22 Control flow: Flow controlled by value of a global variable. Sink functions are in a separate file from sources.
 *
 * */

#include "std_testcase.h"

#include <wchar.h>
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "advapi32")
#pragma comment(lib, "crypt32.lib")

#define HASH_INPUT "ABCDEFG123456" /* INCIDENTAL: Hardcoded crypto */

#ifndef OMITBAD

/* The global variable below is used to drive control flow in the sink function */
int CWE256_Plaintext_Storage_of_Password__w32_char_22_badGlobal = 0;

void CWE256_Plaintext_Storage_of_Password__w32_char_22_badSink(char * data);

void CWE256_Plaintext_Storage_of_Password__w32_char_22_bad()
{
    char * data;
    char dataBuffer[100] = "";
    data = dataBuffer;
    {
        FILE *pFile;
        pFile = fopen("passwords.txt", "r");
        if (pFile != NULL)
        {
            /* POTENTIAL FLAW: Read the password from a file */
            if (fgets(data, 100, pFile) == NULL)
            {
                data[0] = '\0';
            }
            fclose(pFile);
        }
        else
        {
            data[0] = '\0';
        }
    }
    CWE256_Plaintext_Storage_of_Password__w32_char_22_badGlobal = 1; /* true */
    CWE256_Plaintext_Storage_of_Password__w32_char_22_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* The global variables below are used to drive control flow in the sink functions. */
int CWE256_Plaintext_Storage_of_Password__w32_char_22_goodB2G1Global = 0;
int CWE256_Plaintext_Storage_of_Password__w32_char_22_goodB2G2Global = 0;
int CWE256_Plaintext_Storage_of_Password__w32_char_22_goodG2BGlobal = 0;

/* goodB2G1() - use badsource and goodsink by setting the static variable to false instead of true */
void CWE256_Plaintext_Storage_of_Password__w32_char_22_goodB2G1Sink(char * data);

static void goodB2G1()
{
    char * data;
    char dataBuffer[100] = "";
    data = dataBuffer;
    {
        FILE *pFile;
        pFile = fopen("passwords.txt", "r");
        if (pFile != NULL)
        {
            /* POTENTIAL FLAW: Read the password from a file */
            if (fgets(data, 100, pFile) == NULL)
            {
                data[0] = '\0';
            }
            fclose(pFile);
        }
        else
        {
            data[0] = '\0';
        }
    }
    CWE256_Plaintext_Storage_of_Password__w32_char_22_goodB2G1Global = 0; /* false */
    CWE256_Plaintext_Storage_of_Password__w32_char_22_goodB2G1Sink(data);
}

/* goodB2G2() - use badsource and goodsink by reversing the blocks in the if in the sink function */
void CWE256_Plaintext_Storage_of_Password__w32_char_22_goodB2G2Sink(char * data);

static void goodB2G2()
{
    char * data;
    char dataBuffer[100] = "";
    data = dataBuffer;
    {
        FILE *pFile;
        pFile = fopen("passwords.txt", "r");
        if (pFile != NULL)
        {
            /* POTENTIAL FLAW: Read the password from a file */
            if (fgets(data, 100, pFile) == NULL)
            {
                data[0] = '\0';
            }
            fclose(pFile);
        }
        else
        {
            data[0] = '\0';
        }
    }
    CWE256_Plaintext_Storage_of_Password__w32_char_22_goodB2G2Global = 1; /* true */
    CWE256_Plaintext_Storage_of_Password__w32_char_22_goodB2G2Sink(data);
}

/* goodG2B() - use goodsource and badsink */
void CWE256_Plaintext_Storage_of_Password__w32_char_22_goodG2BSink(char * data);

static void goodG2B()
{
    char * data;
    char dataBuffer[100] = "";
    data = dataBuffer;
    {
        FILE *pFile;
        HCRYPTPROV hCryptProv = 0;
        HCRYPTHASH hHash = 0;
        HCRYPTKEY hKey = 0;
        char hashData[100] = HASH_INPUT;
        pFile = fopen("passwords.txt", "r");
        if (pFile != NULL)
        {
            if (fgets(data, 100, pFile) == NULL)
            {
                data[0] = '\0';
            }
            fclose(pFile);
        }
        else
        {
            data[0] = '\0';
        }
        do
        {
            BYTE payload[(100 - 1) * sizeof(char)]; /* same size as data except for NUL terminator */
            DWORD payloadBytes;
            /* Hex-decode the input string into raw bytes */
            payloadBytes = decodeHexChars(payload, sizeof(payload), data);
            /* Wipe the hex string, to prevent it from being given to LogonUserA if
             * any of the crypto calls fail. */
            SecureZeroMemory(data, 100 * sizeof(char));
            /* Aquire a Context */
            if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0))
            {
                break;
            }
            /* Create hash handle */
            if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash))
            {
                break;
            }
            /* Hash the input string */
            if(!CryptHashData(hHash, (BYTE*)hashData, strlen(hashData), 0))
            {
                break;
            }
            /* Derive an AES key from the hash */
            if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey))
            {
                break;
            }
            /* FIX: Decrypt the password before passing it to the sink */
            if(!CryptDecrypt(hKey, 0, 1, 0, payload, &payloadBytes))
            {
                break;
            }
            /* Copy back into data and NUL-terminate */
            memcpy(data, payload, payloadBytes);
            data[payloadBytes / sizeof(char)] = '\0';
        }
        while (0);
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
    CWE256_Plaintext_Storage_of_Password__w32_char_22_goodG2BGlobal = 1; /* true */
    CWE256_Plaintext_Storage_of_Password__w32_char_22_goodG2BSink(data);
}

void CWE256_Plaintext_Storage_of_Password__w32_char_22_good()
{
    goodB2G1();
    goodB2G2();
    goodG2B();
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
    CWE256_Plaintext_Storage_of_Password__w32_char_22_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE256_Plaintext_Storage_of_Password__w32_char_22_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
