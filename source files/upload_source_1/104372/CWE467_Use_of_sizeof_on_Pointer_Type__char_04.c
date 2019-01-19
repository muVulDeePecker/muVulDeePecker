/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE467_Use_of_sizeof_on_Pointer_Type__char_04.c
Label Definition File: CWE467_Use_of_sizeof_on_Pointer_Type.label.xml
Template File: point-flaw-04.tmpl.c
*/
/*
 * @description
 * CWE: 467 Use of sizeof() on a Pointer Type
 * Sinks: char
 *    GoodSink: Use sizeof() the data type
 *    BadSink : Use sizeof() the pointer and not the data type
 * Flow Variant: 04 Control flow: if(STATIC_CONST_TRUE) and if(STATIC_CONST_FALSE)
 *
 * */

#include "std_testcase.h"

/* The two variables below are declared "const", so a tool should
   be able to identify that reads of these will always return their
   initialized values. */
static const int STATIC_CONST_TRUE = 1; /* true */
static const int STATIC_CONST_FALSE = 0; /* false */

#ifndef OMITBAD

void CWE467_Use_of_sizeof_on_Pointer_Type__char_04_bad()
{
    if(STATIC_CONST_TRUE)
    {
        {
            char * badChar = NULL;
            /* FLAW: Using sizeof the pointer and not the data type in malloc() */
            badChar = (char *)malloc(sizeof(badChar));
            *badChar = 'B';
            printHexCharLine(*badChar);
            free(badChar);
        }
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good1() uses if(STATIC_CONST_FALSE) instead of if(STATIC_CONST_TRUE) */
static void good1()
{
    if(STATIC_CONST_FALSE)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        {
            char * goodChar = NULL;
            /* FIX: Using sizeof the data type in malloc() */
            goodChar = (char *)malloc(sizeof(*goodChar));
            *goodChar = 'G';
            printHexCharLine(*goodChar);
            free(goodChar);
        }
    }
}

/* good2() reverses the bodies in the if statement */
static void good2()
{
    if(STATIC_CONST_TRUE)
    {
        {
            char * goodChar = NULL;
            /* FIX: Using sizeof the data type in malloc() */
            goodChar = (char *)malloc(sizeof(*goodChar));
            *goodChar = 'G';
            printHexCharLine(*goodChar);
            free(goodChar);
        }
    }
}

void CWE467_Use_of_sizeof_on_Pointer_Type__char_04_good()
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
    CWE467_Use_of_sizeof_on_Pointer_Type__char_04_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE467_Use_of_sizeof_on_Pointer_Type__char_04_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
