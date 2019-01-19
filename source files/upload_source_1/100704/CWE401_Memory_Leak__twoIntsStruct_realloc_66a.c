/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE401_Memory_Leak__twoIntsStruct_realloc_66a.c
Label Definition File: CWE401_Memory_Leak.c.label.xml
Template File: sources-sinks-66a.tmpl.c
*/
/*
 * @description
 * CWE: 401 Memory Leak
 * BadSource: realloc Allocate data using realloc()
 * GoodSource: Allocate data on the stack
 * Sinks:
 *    GoodSink: call free() on data
 *    BadSink : no deallocation of data
 * Flow Variant: 66 Data flow: data passed in an array from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

/* bad function declaration */
void CWE401_Memory_Leak__twoIntsStruct_realloc_66b_badSink(twoIntsStruct * dataArray[]);

void CWE401_Memory_Leak__twoIntsStruct_realloc_66_bad()
{
    twoIntsStruct * data;
    twoIntsStruct * dataArray[5];
    data = NULL;
    /* POTENTIAL FLAW: Allocate memory on the heap */
    data = (twoIntsStruct *)realloc(data, 100*sizeof(twoIntsStruct));
    /* Initialize and make use of data */
    data[0].intOne = 0;
    data[0].intTwo = 0;
    printStructLine(&data[0]);
    /* put data in array */
    dataArray[2] = data;
    CWE401_Memory_Leak__twoIntsStruct_realloc_66b_badSink(dataArray);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE401_Memory_Leak__twoIntsStruct_realloc_66b_goodG2BSink(twoIntsStruct * dataArray[]);

static void goodG2B()
{
    twoIntsStruct * data;
    twoIntsStruct * dataArray[5];
    data = NULL;
    /* FIX: Use memory allocated on the stack with ALLOCA */
    data = (twoIntsStruct *)ALLOCA(100*sizeof(twoIntsStruct));
    /* Initialize and make use of data */
    data[0].intOne = 0;
    data[0].intTwo = 0;
    printStructLine(&data[0]);
    dataArray[2] = data;
    CWE401_Memory_Leak__twoIntsStruct_realloc_66b_goodG2BSink(dataArray);
}

/* goodB2G uses the BadSource with the GoodSink */
void CWE401_Memory_Leak__twoIntsStruct_realloc_66b_goodB2GSink(twoIntsStruct * dataArray[]);

static void goodB2G()
{
    twoIntsStruct * data;
    twoIntsStruct * dataArray[5];
    data = NULL;
    /* POTENTIAL FLAW: Allocate memory on the heap */
    data = (twoIntsStruct *)realloc(data, 100*sizeof(twoIntsStruct));
    /* Initialize and make use of data */
    data[0].intOne = 0;
    data[0].intTwo = 0;
    printStructLine(&data[0]);
    dataArray[2] = data;
    CWE401_Memory_Leak__twoIntsStruct_realloc_66b_goodB2GSink(dataArray);
}

void CWE401_Memory_Leak__twoIntsStruct_realloc_66_good()
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
    CWE401_Memory_Leak__twoIntsStruct_realloc_66_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE401_Memory_Leak__twoIntsStruct_realloc_66_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
