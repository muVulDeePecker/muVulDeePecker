/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_rand_67a.c
Label Definition File: CWE789_Uncontrolled_Mem_Alloc__malloc.label.xml
Template File: sources-sinks-67a.tmpl.c
*/
/*
 * @description
 * CWE: 789 Uncontrolled Memory Allocation
 * BadSource: rand Set data to result of rand(), which may be zero
 * GoodSource: Small number greater than zero
 * Sinks:
 *    GoodSink: Allocate memory with malloc() and check the size of the memory to be allocated
 *    BadSink : Allocate memory with malloc(), but incorrectly check the size of the memory to be allocated
 * Flow Variant: 67 Data flow: data passed in a struct from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#ifndef _WIN32
#include <wchar.h>
#endif

#define HELLO_STRING L"hello"

typedef struct _CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_rand_67_structType
{
    size_t structFirst;
} CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_rand_67_structType;

#ifndef OMITBAD

/* bad function declaration */
void CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_rand_67b_badSink(CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_rand_67_structType myStruct);

void CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_rand_67_bad()
{
    size_t data;
    CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_rand_67_structType myStruct;
    /* Initialize data */
    data = 0;
    /* POTENTIAL FLAW: Set data to a random value */
    data = rand();
    myStruct.structFirst = data;
    CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_rand_67b_badSink(myStruct);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_rand_67b_goodG2BSink(CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_rand_67_structType myStruct);

static void goodG2B()
{
    size_t data;
    CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_rand_67_structType myStruct;
    /* Initialize data */
    data = 0;
    /* FIX: Use a relatively small number for memory allocation */
    data = 20;
    myStruct.structFirst = data;
    CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_rand_67b_goodG2BSink(myStruct);
}

/* goodB2G uses the BadSource with the GoodSink */
void CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_rand_67b_goodB2GSink(CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_rand_67_structType myStruct);

static void goodB2G()
{
    size_t data;
    CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_rand_67_structType myStruct;
    /* Initialize data */
    data = 0;
    /* POTENTIAL FLAW: Set data to a random value */
    data = rand();
    myStruct.structFirst = data;
    CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_rand_67b_goodB2GSink(myStruct);
}

void CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_rand_67_good()
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
    CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_rand_67_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_rand_67_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
