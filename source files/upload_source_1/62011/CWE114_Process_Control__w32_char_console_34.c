/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE114_Process_Control__w32_char_console_34.c
Label Definition File: CWE114_Process_Control__w32.label.xml
Template File: sources-sink-34.tmpl.c
*/
/*
 * @description
 * CWE: 114 Process Control
 * BadSource: console Read input from the console
 * GoodSource: Hard code the full pathname to the library
 * Sinks:
 *    BadSink : Load a dynamic link library
 * Flow Variant: 34 Data flow: use of a union containing two methods of accessing the same data (within the same function)
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#include <windows.h>

typedef union
{
    char * unionFirst;
    char * unionSecond;
} CWE114_Process_Control__w32_char_console_34_unionType;

#ifndef OMITBAD

void CWE114_Process_Control__w32_char_console_34_bad()
{
    char * data;
    CWE114_Process_Control__w32_char_console_34_unionType myUnion;
    char dataBuffer[100] = "";
    data = dataBuffer;
    {
        /* Read input from the console */
        size_t dataLen = strlen(data);
        /* if there is room in data, read into it from the console */
        if (100-dataLen > 1)
        {
            /* POTENTIAL FLAW: Read data from the console */
            if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL)
            {
                /* The next few lines remove the carriage return from the string that is
                 * inserted by fgets() */
                dataLen = strlen(data);
                if (dataLen > 0 && data[dataLen-1] == '\n')
                {
                    data[dataLen-1] = '\0';
                }
            }
            else
            {
                printLine("fgets() failed");
                /* Restore NUL terminator if fgets fails */
                data[dataLen] = '\0';
            }
        }
    }
    myUnion.unionFirst = data;
    {
        char * data = myUnion.unionSecond;
        {
            HMODULE hModule;
            /* POTENTIAL FLAW: If the path to the library is not specified, an attacker may be able to
             * replace his own file with the intended library */
            hModule = LoadLibraryA(data);
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
    char * data;
    CWE114_Process_Control__w32_char_console_34_unionType myUnion;
    char dataBuffer[100] = "";
    data = dataBuffer;
    /* FIX: Specify the full pathname for the library */
    strcpy(data, "C:\\Windows\\System32\\winsrv.dll");
    myUnion.unionFirst = data;
    {
        char * data = myUnion.unionSecond;
        {
            HMODULE hModule;
            /* POTENTIAL FLAW: If the path to the library is not specified, an attacker may be able to
             * replace his own file with the intended library */
            hModule = LoadLibraryA(data);
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

void CWE114_Process_Control__w32_char_console_34_good()
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
    CWE114_Process_Control__w32_char_console_34_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE114_Process_Control__w32_char_console_34_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
