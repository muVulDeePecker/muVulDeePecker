/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE126_Buffer_Overread__CWE170_char_memcpy_12.c
Label Definition File: CWE126_Buffer_Overread__CWE170.label.xml
Template File: point-flaw-12.tmpl.c
*/
/*
 * @description
 * CWE: 126 Buffer Overread
 * Sinks: memcpy
 *    GoodSink: Copy a string using memcpy with explicit null termination
 *    BadSink : Copy a string using memcpy without explicit null termination
 * Flow Variant: 12 Control flow: if(globalReturnsTrueOrFalse())
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

void CWE126_Buffer_Overread__CWE170_char_memcpy_12_bad()
{
    if(globalReturnsTrueOrFalse())
    {
        {
            char data[150], dest[100];
            /* Initialize data */
            memset(data, 'A', 149);
            data[149] = '\0';
            memcpy(dest, data, 99*sizeof(char));
            /* FLAW: do not explicitly null terminate dest after the use of memcpy */
            printLine(dest);
        }
    }
    else
    {
        {
            char data[150], dest[100];
            /* Initialize data */
            memset(data, 'A', 149);
            data[149] = '\0';
            memcpy(dest, data, 99*sizeof(char));
            dest[99] = '\0'; /* FIX: null terminate dest */
            printLine(dest);
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
            char data[150], dest[100];
            /* Initialize data */
            memset(data, 'A', 149);
            data[149] = '\0';
            memcpy(dest, data, 99*sizeof(char));
            dest[99] = '\0'; /* FIX: null terminate dest */
            printLine(dest);
        }
    }
    else
    {
        {
            char data[150], dest[100];
            /* Initialize data */
            memset(data, 'A', 149);
            data[149] = '\0';
            memcpy(dest, data, 99*sizeof(char));
            dest[99] = '\0'; /* FIX: null terminate dest */
            printLine(dest);
        }
    }
}

void CWE126_Buffer_Overread__CWE170_char_memcpy_12_good()
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
    CWE126_Buffer_Overread__CWE170_char_memcpy_12_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE126_Buffer_Overread__CWE170_char_memcpy_12_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
