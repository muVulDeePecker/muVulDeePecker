/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE401_Memory_Leak__struct_twoIntsStruct_malloc_42.c
Label Definition File: CWE401_Memory_Leak.c.label.xml
Template File: sources-sinks-42.tmpl.c
*/
/*
 * @description
 * CWE: 401 Memory Leak
 * BadSource: malloc Allocate data using malloc()
 * GoodSource: Allocate data on the stack
 * Sinks:
 *    GoodSink: call free() on data
 *    BadSink : no deallocation of data
 * Flow Variant: 42 Data flow: data returned from one function to another in the same source file
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

static struct _twoIntsStruct * badSource(struct _twoIntsStruct * data)
{

    /* POTENTIAL FLAW: Allocate memory on the heap */
    data = (struct _twoIntsStruct *)malloc(100*sizeof(struct _twoIntsStruct));

    /* Initialize and make use of data */

    data[0].intOne = 0;
    data[0].intTwo = 0;

    printStructLine((twoIntsStruct *)&data[0]);

    return data;
}

void CWE401_Memory_Leak__struct_twoIntsStruct_malloc_42_bad()
{
    struct _twoIntsStruct * data;
    data = NULL;
    data = badSource(data);
    /* POTENTIAL FLAW: No deallocation */
    ; /* empty statement needed for some flow variants */
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
static struct _twoIntsStruct * goodG2BSource(struct _twoIntsStruct * data)
{

    /* FIX: Use memory allocated on the stack with ALLOCA */
    data = (struct _twoIntsStruct *)ALLOCA(100*sizeof(struct _twoIntsStruct));

    /* Initialize and make use of data */

    data[0].intOne = 0;
    data[0].intTwo = 0;

    printStructLine((twoIntsStruct *)&data[0]);

    return data;
}

static void goodG2B()
{
    struct _twoIntsStruct * data;
    data = NULL;
    data = goodG2BSource(data);
    /* POTENTIAL FLAW: No deallocation */
    ; /* empty statement needed for some flow variants */
}

/* goodB2G uses the BadSource with the GoodSink */
static struct _twoIntsStruct * goodB2GSource(struct _twoIntsStruct * data)
{

    /* POTENTIAL FLAW: Allocate memory on the heap */
    data = (struct _twoIntsStruct *)malloc(100*sizeof(struct _twoIntsStruct));

    /* Initialize and make use of data */

    data[0].intOne = 0;
    data[0].intTwo = 0;

    printStructLine((twoIntsStruct *)&data[0]);

    return data;
}

static void goodB2G()
{
    struct _twoIntsStruct * data;
    data = NULL;
    data = goodB2GSource(data);
    /* FIX: Deallocate memory */
    free(data);
}

void CWE401_Memory_Leak__struct_twoIntsStruct_malloc_42_good()
{
    goodB2G();
    goodG2B();
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
    CWE401_Memory_Leak__struct_twoIntsStruct_malloc_42_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE401_Memory_Leak__struct_twoIntsStruct_malloc_42_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
