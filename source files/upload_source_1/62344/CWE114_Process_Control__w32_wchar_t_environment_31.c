/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE114_Process_Control__w32_wchar_t_environment_31.c
Label Definition File: CWE114_Process_Control__w32.label.xml
Template File: sources-sink-31.tmpl.c
*/
/*
 * @description
 * CWE: 114 Process Control
 * BadSource: environment Read input from an environment variable
 * GoodSource: Hard code the full pathname to the library
 * Sinks:
 *    BadSink : Load a dynamic link library
 * Flow Variant: 31 Data flow using a copy of data within the same function
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#define ENV_VARIABLE L"ADD"

#ifdef _WIN32
#define GETENV _wgetenv
#else
#define GETENV getenv
#endif

#include <windows.h>

#ifndef OMITBAD

void CWE114_Process_Control__w32_wchar_t_environment_31_bad()
{
    wchar_t * data;
    wchar_t dataBuffer[100] = L"";
    data = dataBuffer;
    {
        /* Append input from an environment variable to data */
        size_t dataLen = wcslen(data);
        wchar_t * environment = GETENV(ENV_VARIABLE);
        /* If there is data in the environment variable */
        if (environment != NULL)
        {
            /* POTENTIAL FLAW: Read data from an environment variable */
            wcsncat(data+dataLen, environment, 100-dataLen-1);
        }
    }
    {
        wchar_t * dataCopy = data;
        wchar_t * data = dataCopy;
        {
            HMODULE hModule;
            /* POTENTIAL FLAW: If the path to the library is not specified, an attacker may be able to
             * replace his own file with the intended library */
            hModule = LoadLibraryW(data);
            if (hModule != NULL)
            {
                FreeLibrary(hModule);
                printLine("Library loaded and freed successfully");
            }
            else
            {
                printLine("Unable to load library");
            }
        }
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B() uses the GoodSource with the BadSink */
static void goodG2B()
{
    wchar_t * data;
    wchar_t dataBuffer[100] = L"";
    data = dataBuffer;
    /* FIX: Specify the full pathname for the library */
    wcscpy(data, L"C:\\Windows\\System32\\winsrv.dll");
    {
        wchar_t * dataCopy = data;
        wchar_t * data = dataCopy;
        {
            HMODULE hModule;
            /* POTENTIAL FLAW: If the path to the library is not specified, an attacker may be able to
             * replace his own file with the intended library */
            hModule = LoadLibraryW(data);
            if (hModule != NULL)
            {
                FreeLibrary(hModule);
                printLine("Library loaded and freed successfully");
            }
            else
            {
                printLine("Unable to load library");
            }
        }
    }
}

void CWE114_Process_Control__w32_wchar_t_environment_31_good()
{
    goodG2B();
}

#endif /* OMITGOOD */

/* Below is the main(). It is only used when building this testcase on
 * its own for testing or for building a binary to use in testing binary
 * analysis tools. It is not used when compiling all the testcases as one
 * application, which is how source code analysis tools are tested.
 */
#ifdef INCLUDEMAIN

int main(int argc, char * argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
    printLine("Calling good()...");
    CWE114_Process_Control__w32_wchar_t_environment_31_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE114_Process_Control__w32_wchar_t_environment_31_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
