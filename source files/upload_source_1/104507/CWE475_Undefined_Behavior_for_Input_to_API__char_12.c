/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE475_Undefined_Behavior_for_Input_to_API__char_12.c
Label Definition File: CWE475_Undefined_Behavior_for_Input_to_API.label.xml
Template File: point-flaw-12.tmpl.c
*/
/*
 * @description
 * CWE: 475 Undefined Behavior for Input to API
 * Sinks:
 *    GoodSink: Copy overlapping memory regions using memmove()
 *    BadSink : Copy overlapping memory regions using memcpy()
 * Flow Variant: 12 Control flow: if(globalReturnsTrueOrFalse())
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

void CWE475_Undefined_Behavior_for_Input_to_API__char_12_bad()
{
    if(globalReturnsTrueOrFalse())
    {
        {
            char dataBuffer[100] = "";
            char * data = dataBuffer;
            strcpy(data, "abcdefghijklmnopqrstuvwxyz");
            /* FLAW: Copy overlapping memory regions using memcpy() for which the result is undefined */
            memcpy(data + 6, data + 4, 10*sizeof(char));
            printLine(data);
        }
    }
    else
    {
        {
            char dataBuffer[100] = "";
            char * data = dataBuffer;
            strcpy(data, "abcdefghijklmnopqrstuvwxyz");
            /* FIX: Copy overlapping memory regions using memmove() */
            memmove(data + 6, data + 4, 10*sizeof(char));
            printLine(data);
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
            char dataBuffer[100] = "";
            char * data = dataBuffer;
            strcpy(data, "abcdefghijklmnopqrstuvwxyz");
            /* FIX: Copy overlapping memory regions using memmove() */
            memmove(data + 6, data + 4, 10*sizeof(char));
            printLine(data);
        }
    }
    else
    {
        {
            char dataBuffer[100] = "";
            char * data = dataBuffer;
            strcpy(data, "abcdefghijklmnopqrstuvwxyz");
            /* FIX: Copy overlapping memory regions using memmove() */
            memmove(data + 6, data + 4, 10*sizeof(char));
            printLine(data);
        }
    }
}

void CWE475_Undefined_Behavior_for_Input_to_API__char_12_good()
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
    CWE475_Undefined_Behavior_for_Input_to_API__char_12_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE475_Undefined_Behavior_for_Input_to_API__char_12_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
