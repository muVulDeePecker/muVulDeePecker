/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE467_Use_of_sizeof_on_Pointer_Type__char_16.c
Label Definition File: CWE467_Use_of_sizeof_on_Pointer_Type.label.xml
Template File: point-flaw-16.tmpl.c
*/
/*
 * @description
 * CWE: 467 Use of sizeof() on a Pointer Type
 * Sinks: char
 *    GoodSink: Use sizeof() the data type
 *    BadSink : Use sizeof() the pointer and not the data type
 * Flow Variant: 16 Control flow: while(1)
 *
 * */

#include "std_testcase.h"

#ifndef OMITBAD

void CWE467_Use_of_sizeof_on_Pointer_Type__char_16_bad()
{
    while(1)
    {
        {
            char * badChar = NULL;
            /* FLAW: Using sizeof the pointer and not the data type in malloc() */
            badChar = (char *)malloc(sizeof(badChar));
            *badChar = 'B';
            printHexCharLine(*badChar);
            free(badChar);
        }
        break;
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good1() uses the GoodSinkBody in the while loop */
static void good1()
{
    while(1)
    {
        {
            char * goodChar = NULL;
            /* FIX: Using sizeof the data type in malloc() */
            goodChar = (char *)malloc(sizeof(*goodChar));
            *goodChar = 'G';
            printHexCharLine(*goodChar);
            free(goodChar);
        }
        break;
    }
}

void CWE467_Use_of_sizeof_on_Pointer_Type__char_16_good()
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
    CWE467_Use_of_sizeof_on_Pointer_Type__char_16_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE467_Use_of_sizeof_on_Pointer_Type__char_16_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
