/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE690_NULL_Deref_From_Return__wchar_t_calloc_21.c
Label Definition File: CWE690_NULL_Deref_From_Return.free.label.xml
Template File: source-sinks-21.tmpl.c
*/
/*
 * @description
 * CWE: 690 Unchecked Return Value To NULL Pointer
 * BadSource: calloc Allocate data using calloc()
 * Sinks:
 *    GoodSink: Check to see if the data allocation failed and if not, use data
 *    BadSink : Don't check for NULL and use data
 * Flow Variant: 21 Control flow: Flow controlled by value of a static global variable. All functions contained in one file.
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

/* The static variable below is used to drive control flow in the sink function */
static int badStatic = 0;

static void badSink(wchar_t * data)
{
    if(badStatic)
    {
        /* FLAW: Initialize memory buffer without checking to see if the memory allocation function failed */
        wcscpy(data, L"Initialize");
        printWLine(data);
        free(data);
    }
}

void CWE690_NULL_Deref_From_Return__wchar_t_calloc_21_bad()
{
    wchar_t * data;
    data = NULL; /* Initialize data */
    /* POTENTIAL FLAW: Allocate memory without checking if the memory allocation function failed */
    data = (wchar_t *)calloc(20, sizeof(wchar_t));
    badStatic = 1; /* true */
    badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* The static variables below are used to drive control flow in the sink functions. */
static int goodB2G1Static = 0;
static int goodB2G2Static = 0;

/* goodB2G1() - use badsource and goodsink by setting the static variable to false instead of true */
static void goodB2G1Sink(wchar_t * data)
{
    if(goodB2G1Static)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        /* FIX: Check to see if the memory allocation function was successful before initializing the memory buffer */
        if (data != NULL)
        {
            wcscpy(data, L"Initialize");
            printWLine(data);
            free(data);
        }
    }
}

static void goodB2G1()
{
    wchar_t * data;
    data = NULL; /* Initialize data */
    /* POTENTIAL FLAW: Allocate memory without checking if the memory allocation function failed */
    data = (wchar_t *)calloc(20, sizeof(wchar_t));
    goodB2G1Static = 0; /* false */
    goodB2G1Sink(data);
}

/* goodB2G2() - use badsource and goodsink by reversing the blocks in the if in the sink function */
static void goodB2G2Sink(wchar_t * data)
{
    if(goodB2G2Static)
    {
        /* FIX: Check to see if the memory allocation function was successful before initializing the memory buffer */
        if (data != NULL)
        {
            wcscpy(data, L"Initialize");
            printWLine(data);
            free(data);
        }
    }
}

static void goodB2G2()
{
    wchar_t * data;
    data = NULL; /* Initialize data */
    /* POTENTIAL FLAW: Allocate memory without checking if the memory allocation function failed */
    data = (wchar_t *)calloc(20, sizeof(wchar_t));
    goodB2G2Static = 1; /* true */
    goodB2G2Sink(data);
}

void CWE690_NULL_Deref_From_Return__wchar_t_calloc_21_good()
{
    goodB2G1();
    goodB2G2();
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
    CWE690_NULL_Deref_From_Return__wchar_t_calloc_21_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE690_NULL_Deref_From_Return__wchar_t_calloc_21_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
