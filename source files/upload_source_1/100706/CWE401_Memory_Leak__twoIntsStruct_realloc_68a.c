/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE401_Memory_Leak__twoIntsStruct_realloc_68a.c
Label Definition File: CWE401_Memory_Leak.c.label.xml
Template File: sources-sinks-68a.tmpl.c
*/
/*
 * @description
 * CWE: 401 Memory Leak
 * BadSource: realloc Allocate data using realloc()
 * GoodSource: Allocate data on the stack
 * Sinks:
 *    GoodSink: call free() on data
 *    BadSink : no deallocation of data
 * Flow Variant: 68 Data flow: data passed as a global variable from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

twoIntsStruct * CWE401_Memory_Leak__twoIntsStruct_realloc_68_badData;
twoIntsStruct * CWE401_Memory_Leak__twoIntsStruct_realloc_68_goodG2BData;
twoIntsStruct * CWE401_Memory_Leak__twoIntsStruct_realloc_68_goodB2GData;

#ifndef OMITBAD

/* bad function declaration */
void CWE401_Memory_Leak__twoIntsStruct_realloc_68b_badSink();

void CWE401_Memory_Leak__twoIntsStruct_realloc_68_bad()
{
    twoIntsStruct * data;
    data = NULL;
    /* POTENTIAL FLAW: Allocate memory on the heap */
    data = (twoIntsStruct *)realloc(data, 100*sizeof(twoIntsStruct));
    /* Initialize and make use of data */
    data[0].intOne = 0;
    data[0].intTwo = 0;
    printStructLine(&data[0]);
    CWE401_Memory_Leak__twoIntsStruct_realloc_68_badData = data;
    CWE401_Memory_Leak__twoIntsStruct_realloc_68b_badSink();
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good function declarations */
void CWE401_Memory_Leak__twoIntsStruct_realloc_68b_goodG2BSink();
void CWE401_Memory_Leak__twoIntsStruct_realloc_68b_goodB2GSink();

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B()
{
    twoIntsStruct * data;
    data = NULL;
    /* FIX: Use memory allocated on the stack with ALLOCA */
    data = (twoIntsStruct *)ALLOCA(100*sizeof(twoIntsStruct));
    /* Initialize and make use of data */
    data[0].intOne = 0;
    data[0].intTwo = 0;
    printStructLine(&data[0]);
    CWE401_Memory_Leak__twoIntsStruct_realloc_68_goodG2BData = data;
    CWE401_Memory_Leak__twoIntsStruct_realloc_68b_goodG2BSink();
}

/* goodB2G uses the BadSource with the GoodSink */
static void goodB2G()
{
    twoIntsStruct * data;
    data = NULL;
    /* POTENTIAL FLAW: Allocate memory on the heap */
    data = (twoIntsStruct *)realloc(data, 100*sizeof(twoIntsStruct));
    /* Initialize and make use of data */
    data[0].intOne = 0;
    data[0].intTwo = 0;
    printStructLine(&data[0]);
    CWE401_Memory_Leak__twoIntsStruct_realloc_68_goodB2GData = data;
    CWE401_Memory_Leak__twoIntsStruct_realloc_68b_goodB2GSink();
}

void CWE401_Memory_Leak__twoIntsStruct_realloc_68_good()
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
    CWE401_Memory_Leak__twoIntsStruct_realloc_68_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE401_Memory_Leak__twoIntsStruct_realloc_68_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
