/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE401_Memory_Leak__int64_t_malloc_61a.c
Label Definition File: CWE401_Memory_Leak.c.label.xml
Template File: sources-sinks-61a.tmpl.c
*/
/*
 * @description
 * CWE: 401 Memory Leak
 * BadSource: malloc Allocate data using malloc()
 * GoodSource: Allocate data on the stack
 * Sinks:
 *    GoodSink: call free() on data
 *    BadSink : no deallocation of data
 * Flow Variant: 61 Data flow: data returned from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

/* bad function declaration */
int64_t * CWE401_Memory_Leak__int64_t_malloc_61b_badSource(int64_t * data);

void CWE401_Memory_Leak__int64_t_malloc_61_bad()
{
    int64_t * data;
    data = NULL;
    data = CWE401_Memory_Leak__int64_t_malloc_61b_badSource(data);
    /* POTENTIAL FLAW: No deallocation */
    ; /* empty statement needed for some flow variants */
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
int64_t * CWE401_Memory_Leak__int64_t_malloc_61b_goodG2BSource(int64_t * data);

static void goodG2B()
{
    int64_t * data;
    data = NULL;
    data = CWE401_Memory_Leak__int64_t_malloc_61b_goodG2BSource(data);
    /* POTENTIAL FLAW: No deallocation */
    ; /* empty statement needed for some flow variants */
}

/* goodB2G uses the BadSource with the GoodSink */
int64_t * CWE401_Memory_Leak__int64_t_malloc_61b_goodB2GSource(int64_t * data);

static void goodB2G()
{
    int64_t * data;
    data = NULL;
    data = CWE401_Memory_Leak__int64_t_malloc_61b_goodB2GSource(data);
    /* FIX: Deallocate memory */
    free(data);
}

void CWE401_Memory_Leak__int64_t_malloc_61_good()
{
    goodG2B();
    goodB2G();
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
    CWE401_Memory_Leak__int64_t_malloc_61_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE401_Memory_Leak__int64_t_malloc_61_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
