/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE401_Memory_Leak__struct_twoIntsStruct_malloc_06.c
Label Definition File: CWE401_Memory_Leak.c.label.xml
Template File: sources-sinks-06.tmpl.c
*/
/*
 * @description
 * CWE: 401 Memory Leak
 * BadSource: malloc Allocate data using malloc()
 * GoodSource: Allocate data on the stack
 * Sinks:
 *    GoodSink: call free() on data
 *    BadSink : no deallocation of data
 * Flow Variant: 06 Control flow: if(STATIC_CONST_FIVE==5) and if(STATIC_CONST_FIVE!=5)
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

/* The variable below is declared "const", so a tool should be able
   to identify that reads of this will always give its initialized
   value. */
static const int STATIC_CONST_FIVE = 5;

#ifndef OMITBAD

void CWE401_Memory_Leak__struct_twoIntsStruct_malloc_06_bad()
{
    struct _twoIntsStruct * data;
    data = NULL;
    if(STATIC_CONST_FIVE==5)
    {
        /* POTENTIAL FLAW: Allocate memory on the heap */
        data = (struct _twoIntsStruct *)malloc(100*sizeof(struct _twoIntsStruct));
        /* Initialize and make use of data */
        data[0].intOne = 0;
        data[0].intTwo = 0;
        printStructLine((twoIntsStruct *)&data[0]);
    }
    if(STATIC_CONST_FIVE==5)
    {
        /* POTENTIAL FLAW: No deallocation */
        ; /* empty statement needed for some flow variants */
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G1() - use badsource and goodsink by changing the second STATIC_CONST_FIVE==5 to STATIC_CONST_FIVE!=5 */
static void goodB2G1()
{
    struct _twoIntsStruct * data;
    data = NULL;
    if(STATIC_CONST_FIVE==5)
    {
        /* POTENTIAL FLAW: Allocate memory on the heap */
        data = (struct _twoIntsStruct *)malloc(100*sizeof(struct _twoIntsStruct));
        /* Initialize and make use of data */
        data[0].intOne = 0;
        data[0].intTwo = 0;
        printStructLine((twoIntsStruct *)&data[0]);
    }
    if(STATIC_CONST_FIVE!=5)
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
    struct _twoIntsStruct * data;
    data = NULL;
    if(STATIC_CONST_FIVE==5)
    {
        /* POTENTIAL FLAW: Allocate memory on the heap */
        data = (struct _twoIntsStruct *)malloc(100*sizeof(struct _twoIntsStruct));
        /* Initialize and make use of data */
        data[0].intOne = 0;
        data[0].intTwo = 0;
        printStructLine((twoIntsStruct *)&data[0]);
    }
    if(STATIC_CONST_FIVE==5)
    {
        /* FIX: Deallocate memory */
        free(data);
    }
}

/* goodG2B1() - use goodsource and badsink by changing the first STATIC_CONST_FIVE==5 to STATIC_CONST_FIVE!=5 */
static void goodG2B1()
{
    struct _twoIntsStruct * data;
    data = NULL;
    if(STATIC_CONST_FIVE!=5)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        /* FIX: Use memory allocated on the stack with ALLOCA */
        data = (struct _twoIntsStruct *)ALLOCA(100*sizeof(struct _twoIntsStruct));
        /* Initialize and make use of data */
        data[0].intOne = 0;
        data[0].intTwo = 0;
        printStructLine((twoIntsStruct *)&data[0]);
    }
    if(STATIC_CONST_FIVE==5)
    {
        /* POTENTIAL FLAW: No deallocation */
        ; /* empty statement needed for some flow variants */
    }
}

/* goodG2B2() - use goodsource and badsink by reversing the blocks in the first if */
static void goodG2B2()
{
    struct _twoIntsStruct * data;
    data = NULL;
    if(STATIC_CONST_FIVE==5)
    {
        /* FIX: Use memory allocated on the stack with ALLOCA */
        data = (struct _twoIntsStruct *)ALLOCA(100*sizeof(struct _twoIntsStruct));
        /* Initialize and make use of data */
        data[0].intOne = 0;
        data[0].intTwo = 0;
        printStructLine((twoIntsStruct *)&data[0]);
    }
    if(STATIC_CONST_FIVE==5)
    {
        /* POTENTIAL FLAW: No deallocation */
        ; /* empty statement needed for some flow variants */
    }
}

void CWE401_Memory_Leak__struct_twoIntsStruct_malloc_06_good()
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
    CWE401_Memory_Leak__struct_twoIntsStruct_malloc_06_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE401_Memory_Leak__struct_twoIntsStruct_malloc_06_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
