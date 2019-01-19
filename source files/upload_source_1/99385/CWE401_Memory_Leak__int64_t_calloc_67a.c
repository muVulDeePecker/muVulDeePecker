/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE401_Memory_Leak__int64_t_calloc_67a.c
Label Definition File: CWE401_Memory_Leak.c.label.xml
Template File: sources-sinks-67a.tmpl.c
*/
/*
 * @description
 * CWE: 401 Memory Leak
 * BadSource: calloc Allocate data using calloc()
 * GoodSource: Allocate data on the stack
 * Sinks:
 *    GoodSink: call free() on data
 *    BadSink : no deallocation of data
 * Flow Variant: 67 Data flow: data passed in a struct from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

typedef struct _CWE401_Memory_Leak__int64_t_calloc_67_structType
{
    int64_t * structFirst;
} CWE401_Memory_Leak__int64_t_calloc_67_structType;

#ifndef OMITBAD

/* bad function declaration */
void CWE401_Memory_Leak__int64_t_calloc_67b_badSink(CWE401_Memory_Leak__int64_t_calloc_67_structType myStruct);

void CWE401_Memory_Leak__int64_t_calloc_67_bad()
{
    int64_t * data;
    CWE401_Memory_Leak__int64_t_calloc_67_structType myStruct;
    data = NULL;
    /* POTENTIAL FLAW: Allocate memory on the heap */
    data = (int64_t *)calloc(100, sizeof(int64_t));
    /* Initialize and make use of data */
    data[0] = 5LL;
    printLongLongLine(data[0]);
    myStruct.structFirst = data;
    CWE401_Memory_Leak__int64_t_calloc_67b_badSink(myStruct);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE401_Memory_Leak__int64_t_calloc_67b_goodG2BSink(CWE401_Memory_Leak__int64_t_calloc_67_structType myStruct);

static void goodG2B()
{
    int64_t * data;
    CWE401_Memory_Leak__int64_t_calloc_67_structType myStruct;
    data = NULL;
    /* FIX: Use memory allocated on the stack with ALLOCA */
    data = (int64_t *)ALLOCA(100*sizeof(int64_t));
    /* Initialize and make use of data */
    data[0] = 5LL;
    printLongLongLine(data[0]);
    myStruct.structFirst = data;
    CWE401_Memory_Leak__int64_t_calloc_67b_goodG2BSink(myStruct);
}

/* goodB2G uses the BadSource with the GoodSink */
void CWE401_Memory_Leak__int64_t_calloc_67b_goodB2GSink(CWE401_Memory_Leak__int64_t_calloc_67_structType myStruct);

static void goodB2G()
{
    int64_t * data;
    CWE401_Memory_Leak__int64_t_calloc_67_structType myStruct;
    data = NULL;
    /* POTENTIAL FLAW: Allocate memory on the heap */
    data = (int64_t *)calloc(100, sizeof(int64_t));
    /* Initialize and make use of data */
    data[0] = 5LL;
    printLongLongLine(data[0]);
    myStruct.structFirst = data;
    CWE401_Memory_Leak__int64_t_calloc_67b_goodB2GSink(myStruct);
}

void CWE401_Memory_Leak__int64_t_calloc_67_good()
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
    CWE401_Memory_Leak__int64_t_calloc_67_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE401_Memory_Leak__int64_t_calloc_67_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
