/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE665_Improper_Initialization__wchar_t_cat_10.c
Label Definition File: CWE665_Improper_Initialization.label.xml
Template File: sources-sink-10.tmpl.c
*/
/*
 * @description
 * CWE: 665 Improper Initialization
 * BadSource:  Do not initialize data properly
 * GoodSource: Initialize data
 * Sink: cat
 *    BadSink : Copy string to data using wcscat
 * Flow Variant: 10 Control flow: if(globalTrue) and if(globalFalse)
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

void CWE665_Improper_Initialization__wchar_t_cat_10_bad()
{
    wchar_t * data;
    wchar_t dataBuffer[100];
    data = dataBuffer;
    if(globalTrue)
    {
        /* FLAW: Do not initialize data */
        ; /* empty statement needed for some flow variants */
    }
    {
        wchar_t source[100];
        wmemset(source, L'C', 100-1); /* fill with L'C's */
        source[100-1] = L'\0'; /* null terminate */
        /* POTENTIAL FLAW: If data is not initialized properly, wcscat() may not function correctly */
        wcscat(data, source);
        printWLine(data);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B1() - use goodsource and badsink by changing the globalTrue to globalFalse */
static void goodG2B1()
{
    wchar_t * data;
    wchar_t dataBuffer[100];
    data = dataBuffer;
    if(globalFalse)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        /* FIX: Properly initialize data */
        data[0] = L'\0'; /* null terminate */
    }
    {
        wchar_t source[100];
        wmemset(source, L'C', 100-1); /* fill with L'C's */
        source[100-1] = L'\0'; /* null terminate */
        /* POTENTIAL FLAW: If data is not initialized properly, wcscat() may not function correctly */
        wcscat(data, source);
        printWLine(data);
    }
}

/* goodG2B2() - use goodsource and badsink by reversing the blocks in the if statement */
static void goodG2B2()
{
    wchar_t * data;
    wchar_t dataBuffer[100];
    data = dataBuffer;
    if(globalTrue)
    {
        /* FIX: Properly initialize data */
        data[0] = L'\0'; /* null terminate */
    }
    {
        wchar_t source[100];
        wmemset(source, L'C', 100-1); /* fill with L'C's */
        source[100-1] = L'\0'; /* null terminate */
        /* POTENTIAL FLAW: If data is not initialized properly, wcscat() may not function correctly */
        wcscat(data, source);
        printWLine(data);
    }
}

void CWE665_Improper_Initialization__wchar_t_cat_10_good()
{
    goodG2B1();
    goodG2B2();
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
    CWE665_Improper_Initialization__wchar_t_cat_10_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE665_Improper_Initialization__wchar_t_cat_10_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
