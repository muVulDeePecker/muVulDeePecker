/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE226_Sensitive_Information_Uncleared_Before_Release__w32_wchar_t_alloca_09.c
Label Definition File: CWE226_Sensitive_Information_Uncleared_Before_Release__w32.label.xml
Template File: point-flaw-09.tmpl.c
*/
/*
 * @description
 * CWE: 226 Sensitive Information Uncleared Before Release
 * Sinks: alloca
 *    GoodSink: Clear the password buffer before releasing the memory from the stack
 *    BadSink : Release password from the stack without first clearing the buffer
 * Flow Variant: 09 Control flow: if(GLOBAL_CONST_TRUE) and if(GLOBAL_CONST_FALSE)
 *
 * */

#include "std_testcase.h"

#include <wchar.h>
#include <windows.h>
#pragma comment(lib, "advapi32.lib")

#ifndef OMITBAD

void CWE226_Sensitive_Information_Uncleared_Before_Release__w32_wchar_t_alloca_09_bad()
{
    if(GLOBAL_CONST_TRUE)
    {
        {
            wchar_t * password = (wchar_t *)ALLOCA(100*sizeof(wchar_t));
            size_t passwordLen = 0;
            HANDLE hUser;
            wchar_t * username = L"User";
            wchar_t * domain = L"Domain";
            /* Initialize password */
            password[0] = L'\0';
            if (fgetws(password, 100, stdin) == NULL)
            {
                printLine("fgetws() failed");
                /* Restore NUL terminator if fgetws fails */
                password[0] = L'\0';
            }
            /* Remove the carriage return from the string that is inserted by fgetws() */
            passwordLen = wcslen(password);
            if (passwordLen > 0)
            {
                password[passwordLen-1] = L'\0';
            }
            /* Use the password in LogonUser() to establish that it is "sensitive" */
            if (LogonUserW(
                        username,
                        domain,
                        password,
                        LOGON32_LOGON_NETWORK,
                        LOGON32_PROVIDER_DEFAULT,
                        &hUser) != 0)
            {
                printLine("User logged in successfully.");
                CloseHandle(hUser);
            }
            else
            {
                printLine("Unable to login.");
            }
            /* FLAW: Release password from the stack without first clearing the buffer */
        }
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good1() uses if(GLOBAL_CONST_FALSE) instead of if(GLOBAL_CONST_TRUE) */
static void good1()
{
    if(GLOBAL_CONST_FALSE)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        {
            wchar_t * password = (wchar_t *)ALLOCA(100*sizeof(wchar_t));
            size_t passwordLen = 0;
            HANDLE hUser;
            wchar_t * username = L"User";
            wchar_t * domain = L"Domain";
            /* Initialize password */
            password[0] = L'\0';
            if (fgetws(password, 100, stdin) == NULL)
            {
                printLine("fgetws() failed");
                /* Restore NUL terminator if fgetws fails */
                password[0] = L'\0';
            }
            /* Remove the carriage return from the string that is inserted by fgetws() */
            passwordLen = wcslen(password);
            if (passwordLen > 0)
            {
                password[passwordLen-1] = L'\0';
            }
            /* Use the password in LogonUser() to establish that it is "sensitive" */
            if (LogonUserW(
                        username,
                        domain,
                        password,
                        LOGON32_LOGON_NETWORK,
                        LOGON32_PROVIDER_DEFAULT,
                        &hUser) != 0)
            {
                printLine("User logged in successfully.");
                CloseHandle(hUser);
            }
            else
            {
                printLine("Unable to login.");
            }
            passwordLen = wcslen(password);
            /* FIX: Clear password prior to release from stack */
            SecureZeroMemory(password, passwordLen * sizeof(wchar_t));
        }
    }
}

/* good2() reverses the bodies in the if statement */
static void good2()
{
    if(GLOBAL_CONST_TRUE)
    {
        {
            wchar_t * password = (wchar_t *)ALLOCA(100*sizeof(wchar_t));
            size_t passwordLen = 0;
            HANDLE hUser;
            wchar_t * username = L"User";
            wchar_t * domain = L"Domain";
            /* Initialize password */
            password[0] = L'\0';
            if (fgetws(password, 100, stdin) == NULL)
            {
                printLine("fgetws() failed");
                /* Restore NUL terminator if fgetws fails */
                password[0] = L'\0';
            }
            /* Remove the carriage return from the string that is inserted by fgetws() */
            passwordLen = wcslen(password);
            if (passwordLen > 0)
            {
                password[passwordLen-1] = L'\0';
            }
            /* Use the password in LogonUser() to establish that it is "sensitive" */
            if (LogonUserW(
                        username,
                        domain,
                        password,
                        LOGON32_LOGON_NETWORK,
                        LOGON32_PROVIDER_DEFAULT,
                        &hUser) != 0)
            {
                printLine("User logged in successfully.");
                CloseHandle(hUser);
            }
            else
            {
                printLine("Unable to login.");
            }
            passwordLen = wcslen(password);
            /* FIX: Clear password prior to release from stack */
            SecureZeroMemory(password, passwordLen * sizeof(wchar_t));
        }
    }
}

void CWE226_Sensitive_Information_Uncleared_Before_Release__w32_wchar_t_alloca_09_good()
{
    good1();
    good2();
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
    CWE226_Sensitive_Information_Uncleared_Before_Release__w32_wchar_t_alloca_09_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE226_Sensitive_Information_Uncleared_Before_Release__w32_wchar_t_alloca_09_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
