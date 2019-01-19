/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE415_Double_Free__malloc_free_int64_t_11.c
Label Definition File: CWE415_Double_Free__malloc_free.label.xml
Template File: sources-sinks-11.tmpl.c
*/
/*
 * @description
 * CWE: 415 Double Free
 * BadSource:  Allocate data using malloc() and Deallocate data using free()
 * GoodSource: Allocate data using malloc()
 * Sinks:
 *    GoodSink: do nothing
 *    BadSink : Deallocate data using free()
 * Flow Variant: 11 Control flow: if(globalReturnsTrue()) and if(globalReturnsFalse())
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

void CWE415_Double_Free__malloc_free_int64_t_11_bad()
{
    int64_t * data;
    /* Initialize data */
    data = NULL;
    if(globalReturnsTrue())
    {
        data = (int64_t *)malloc(100*sizeof(int64_t));
        /* POTENTIAL FLAW: Free data in the source - the bad sink frees data as well */
        free(data);
    }
    if(globalReturnsTrue())
    {
        /* POTENTIAL FLAW: Possibly freeing memory twice */
        free(data);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G1() - use badsource and goodsink by changing the second globalReturnsTrue() to globalReturnsFalse() */
static void goodB2G1()
{
    int64_t * data;
    /* Initialize data */
    data = NULL;
    if(globalReturnsTrue())
    {
        data = (int64_t *)malloc(100*sizeof(int64_t));
        /* POTENTIAL FLAW: Free data in the source - the bad sink frees data as well */
        free(data);
    }
    if(globalReturnsFalse())
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        /* do nothing */
        /* FIX: Don't attempt to free the memory */
        ; /* empty statement needed for some flow variants */
    }
}

/* goodB2G2() - use badsource and goodsink by reversing the blocks in the second if */
static void goodB2G2()
{
    int64_t * data;
    /* Initialize data */
    data = NULL;
    if(globalReturnsTrue())
    {
        data = (int64_t *)malloc(100*sizeof(int64_t));
        /* POTENTIAL FLAW: Free data in the source - the bad sink frees data as well */
        free(data);
    }
    if(globalReturnsTrue())
    {
        /* do nothing */
        /* FIX: Don't attempt to free the memory */
        ; /* empty statement needed for some flow variants */
    }
}

/* goodG2B1() - use goodsource and badsink by changing the first globalReturnsTrue() to globalReturnsFalse() */
static void goodG2B1()
{
    int64_t * data;
    /* Initialize data */
    data = NULL;
    if(globalReturnsFalse())
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        data = (int64_t *)malloc(100*sizeof(int64_t));
        /* FIX: Do NOT free data in the source - the bad sink frees data */
    }
    if(globalReturnsTrue())
    {
        /* POTENTIAL FLAW: Possibly freeing memory twice */
        free(data);
    }
}

/* goodG2B2() - use goodsource and badsink by reversing the blocks in the first if */
static void goodG2B2()
{
    int64_t * data;
    /* Initialize data */
    data = NULL;
    if(globalReturnsTrue())
    {
        data = (int64_t *)malloc(100*sizeof(int64_t));
        /* FIX: Do NOT free data in the source - the bad sink frees data */
    }
    if(globalReturnsTrue())
    {
        /* POTENTIAL FLAW: Possibly freeing memory twice */
        free(data);
    }
}

void CWE415_Double_Free__malloc_free_int64_t_11_good()
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
    CWE415_Double_Free__malloc_free_int64_t_11_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE415_Double_Free__malloc_free_int64_t_11_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
