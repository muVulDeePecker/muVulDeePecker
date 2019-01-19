/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE256_Plaintext_Storage_of_Password__w32_wchar_t_53a.c
Label Definition File: CWE256_Plaintext_Storage_of_Password__w32.label.xml
Template File: sources-sinks-53a.tmpl.c
*/
/*
 * @description
 * CWE: 256 Plaintext Storage of Password
 * BadSource:  Read the password from a file
 * GoodSource: Read the password from a file and decrypt it
 * Sinks:
 *    GoodSink: Decrypt the password then authenticate the user using LogonUserW()
 *    BadSink : Authenticate the user using LogonUserW()
 * Flow Variant: 53 Data flow: data passed as an argument from one function through two others to a fourth; all four functions are in different source files
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

/* bad function declaration */
void CWE256_Plaintext_Storage_of_Password__w32_wchar_t_53b_badSink(wchar_t * data);

void CWE256_Plaintext_Storage_of_Password__w32_wchar_t_53_bad()
{
    wchar_t * data;
    wchar_t dataBuffer[100] = L"";
    data = dataBuffer;
    {
        FILE *pFile;
        pFile = fopen("passwords.txt", "r");
        if (pFile != NULL)
        {
            /* POTENTIAL FLAW: Read the password from a file */
            if (fgetws(data, 100, pFile) == NULL)
            {
                data[0] = L'\0';
            }
            fclose(pFile);
        }
        else
        {
            data[0] = L'\0';
        }
    }
    CWE256_Plaintext_Storage_of_Password__w32_wchar_t_53b_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE256_Plaintext_Storage_of_Password__w32_wchar_t_53b_goodG2BSink(wchar_t * data);

static void goodG2B()
{
    wchar_t * data;
    wchar_t dataBuffer[100] = L"";
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
            if (fgetws(data, 100, pFile) == NULL)
            {
                data[0] = L'\0';
            }
            fclose(pFile);
        }
        else
        {
            data[0] = L'\0';
        }
        do
        {
            BYTE payload[(100 - 1) * sizeof(wchar_t)]; /* same size as data except for NUL terminator */
            DWORD payloadBytes;
            /* Hex-decode the input string into raw bytes */
            payloadBytes = decodeHexWChars(payload, sizeof(payload), data);
            /* Wipe the hex string, to prevent it from being given to LogonUserW if
             * any of the crypto calls fail. */
            SecureZeroMemory(data, 100 * sizeof(wchar_t));
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
            data[payloadBytes / sizeof(wchar_t)] = L'\0';
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
    CWE256_Plaintext_Storage_of_Password__w32_wchar_t_53b_goodG2BSink(data);
}

/* goodB2G uses the BadSource with the GoodSink */
void CWE256_Plaintext_Storage_of_Password__w32_wchar_t_53b_goodB2GSink(wchar_t * data);

static void goodB2G()
{
    wchar_t * data;
    wchar_t dataBuffer[100] = L"";
    data = dataBuffer;
    {
        FILE *pFile;
        pFile = fopen("passwords.txt", "r");
        if (pFile != NULL)
        {
            /* POTENTIAL FLAW: Read the password from a file */
            if (fgetws(data, 100, pFile) == NULL)
            {
                data[0] = L'\0';
            }
            fclose(pFile);
        }
        else
        {
            data[0] = L'\0';
        }
    }
    CWE256_Plaintext_Storage_of_Password__w32_wchar_t_53b_goodB2GSink(data);
}

void CWE256_Plaintext_Storage_of_Password__w32_wchar_t_53_good()
{
    goodG2B();
    goodB2G();
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
    CWE256_Plaintext_Storage_of_Password__w32_wchar_t_53_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE256_Plaintext_Storage_of_Password__w32_wchar_t_53_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
