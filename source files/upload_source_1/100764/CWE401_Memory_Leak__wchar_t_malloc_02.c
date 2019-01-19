/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE401_Memory_Leak__wchar_t_malloc_02.c
Label Definition File: CWE401_Memory_Leak.c.label.xml
Template File: sources-sinks-02.tmpl.c
*/
/*
 * @description
 * CWE: 401 Memory Leak
 * BadSource: malloc Allocate data using malloc()
 * GoodSource: Allocate data on the stack
 * Sinks:
 *    GoodSink: call free() on data
 *    BadSink : no deallocation of data
 * Flow Variant: 02 Control flow: if(1) and if(0)
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

void CWE401_Memory_Leak__wchar_t_malloc_02_bad()
{
    wchar_t * data;
    data = NULL;
    if(1)
    {
        /* POTENTIAL FLAW: Allocate memory on the heap */
        data = (wchar_t *)malloc(100*sizeof(wchar_t));
        /* Initialize and make use of data */
        wcscpy(data, L"A String");
        printWLine(data);
    }
    if(1)
    {
        /* POTENTIAL FLAW: No deallocation */
        ; /* empty statement needed for some flow variants */
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G1() - use badsource and goodsink by changing the second 1 to 0 */
static void goodB2G1()
{
    wchar_t * data;
    data = NULL;
    if(1)
    {
        /* POTENTIAL FLAW: Allocate memory on the heap */
        data = (wchar_t *)malloc(100*sizeof(wchar_t));
        /* Initialize and make use of data */
        wcscpy(data, L"A String");
        printWLine(data);
    }
    if(0)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        /* FIX: Deallocate memory */
        free(data);
    }
}

/* goodB2G2() - use badsource and goodsink by reversing the blocks in the second if */
static void goodB2G2()
{
    wchar_t * data;
    data = NULL;
    if(1)
    {
        /* POTENTIAL FLAW: Allocate memory on the heap */
        data = (wchar_t *)malloc(100*sizeof(wchar_t));
        /* Initialize and make use of data */
        wcscpy(data, L"A String");
        printWLine(data);
    }
    if(1)
    {
        /* FIX: Deallocate memory */
        free(data);
    }
}

/* goodG2B1() - use goodsource and badsink by changing the first 1 to 0 */
static void goodG2B1()
{
    wchar_t * data;
    data = NULL;
    if(0)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        /* FIX: Use memory allocated on the stack with ALLOCA */
        data = (wchar_t *)ALLOCA(100*sizeof(wchar_t));
        /* Initialize and make use of data */
        wcscpy(data, L"A String");
        printWLine(data);
    }
    if(1)
    {
        /* POTENTIAL FLAW: No deallocation */
        ; /* empty statement needed for some flow variants */
    }
}

/* goodG2B2() - use goodsource and badsink by reversing the blocks in the first if */
static void goodG2B2()
{
    wchar_t * data;
    data = NULL;
    if(1)
    {
        /* FIX: Use memory allocated on the stack with ALLOCA */
        data = (wchar_t *)ALLOCA(100*sizeof(wchar_t));
        /* Initialize and make use of data */
        wcscpy(data, L"A String");
        printWLine(data);
    }
    if(1)
    {
        /* POTENTIAL FLAW: No deallocation */
        ; /* empty statement needed for some flow variants */
    }
}

void CWE401_Memory_Leak__wchar_t_malloc_02_good()
{
    goodB2G1();
    goodB2G2();
    goodG2B1();
    goodG2B2();
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
    CWE401_Memory_Leak__wchar_t_malloc_02_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE401_Memory_Leak__wchar_t_malloc_02_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
