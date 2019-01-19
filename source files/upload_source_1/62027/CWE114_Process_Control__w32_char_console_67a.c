/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE114_Process_Control__w32_char_console_67a.c
Label Definition File: CWE114_Process_Control__w32.label.xml
Template File: sources-sink-67a.tmpl.c
*/
/*
 * @description
 * CWE: 114 Process Control
 * BadSource: console Read input from the console
 * GoodSource: Hard code the full pathname to the library
 * Sinks:
 *    BadSink : Load a dynamic link library
 * Flow Variant: 67 Data flow: data passed in a struct from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#include <windows.h>

typedef struct _CWE114_Process_Control__w32_char_console_67_structType
{
    char * structFirst;
} CWE114_Process_Control__w32_char_console_67_structType;

#ifndef OMITBAD

/* bad function declaration */
void CWE114_Process_Control__w32_char_console_67b_badSink(CWE114_Process_Control__w32_char_console_67_structType myStruct);

void CWE114_Process_Control__w32_char_console_67_bad()
{
    char * data;
    CWE114_Process_Control__w32_char_console_67_structType myStruct;
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
    myStruct.structFirst = data;
    CWE114_Process_Control__w32_char_console_67b_badSink(myStruct);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE114_Process_Control__w32_char_console_67b_goodG2BSink(CWE114_Process_Control__w32_char_console_67_structType myStruct);

static void goodG2B()
{
    char * data;
    CWE114_Process_Control__w32_char_console_67_structType myStruct;
    char dataBuffer[100] = "";
    data = dataBuffer;
    /* FIX: Specify the full pathname for the library */
    strcpy(data, "C:\\Windows\\System32\\winsrv.dll");
    myStruct.structFirst = data;
    CWE114_Process_Control__w32_char_console_67b_goodG2BSink(myStruct);
}

void CWE114_Process_Control__w32_char_console_67_good()
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
    CWE114_Process_Control__w32_char_console_67_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE114_Process_Control__w32_char_console_67_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
