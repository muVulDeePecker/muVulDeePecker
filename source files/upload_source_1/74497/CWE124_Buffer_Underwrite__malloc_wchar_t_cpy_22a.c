/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE124_Buffer_Underwrite__malloc_wchar_t_cpy_22a.c
Label Definition File: CWE124_Buffer_Underwrite__malloc.label.xml
Template File: sources-sink-22a.tmpl.c
*/
/*
 * @description
 * CWE: 124 Buffer Underwrite
 * BadSource:  Set data pointer to before the allocated memory buffer
 * GoodSource: Set data pointer to the allocated memory buffer
 * Sink: cpy
 *    BadSink : Copy string to data using wcscpy
 * Flow Variant: 22 Control flow: Flow controlled by value of a global variable. Sink functions are in a separate file from sources.
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

/* The global variable below is used to drive control flow in the source function */
int CWE124_Buffer_Underwrite__malloc_wchar_t_cpy_22_badGlobal = 0;

wchar_t * CWE124_Buffer_Underwrite__malloc_wchar_t_cpy_22_badSource(wchar_t * data);

void CWE124_Buffer_Underwrite__malloc_wchar_t_cpy_22_bad()
{
    wchar_t * data;
    data = NULL;
    CWE124_Buffer_Underwrite__malloc_wchar_t_cpy_22_badGlobal = 1; /* true */
    data = CWE124_Buffer_Underwrite__malloc_wchar_t_cpy_22_badSource(data);
    {
        wchar_t source[100];
        wmemset(source, L'C', 100-1); /* fill with 'C's */
        source[100-1] = L'\0'; /* null terminate */
        /* POTENTIAL FLAW: Possibly copying data to memory before the destination buffer */
        wcscpy(data, source);
        printWLine(data);
        /* INCIDENTAL CWE-401: Memory Leak - data may not point to location
         * returned by malloc() so can't safely call free() on it */
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* The global variables below are used to drive control flow in the source functions. */
int CWE124_Buffer_Underwrite__malloc_wchar_t_cpy_22_goodG2B1Global = 0;
int CWE124_Buffer_Underwrite__malloc_wchar_t_cpy_22_goodG2B2Global = 0;

/* goodG2B1() - use goodsource and badsink by setting the static variable to false instead of true */
wchar_t * CWE124_Buffer_Underwrite__malloc_wchar_t_cpy_22_goodG2B1Source(wchar_t * data);

static void goodG2B1()
{
    wchar_t * data;
    data = NULL;
    CWE124_Buffer_Underwrite__malloc_wchar_t_cpy_22_goodG2B1Global = 0; /* false */
    data = CWE124_Buffer_Underwrite__malloc_wchar_t_cpy_22_goodG2B1Source(data);
    {
        wchar_t source[100];
        wmemset(source, L'C', 100-1); /* fill with 'C's */
        source[100-1] = L'\0'; /* null terminate */
        /* POTENTIAL FLAW: Possibly copying data to memory before the destination buffer */
        wcscpy(data, source);
        printWLine(data);
        /* INCIDENTAL CWE-401: Memory Leak - data may not point to location
         * returned by malloc() so can't safely call free() on it */
    }
}

/* goodG2B2() - use goodsource and badsink by reversing the blocks in the if in the source function */
wchar_t * CWE124_Buffer_Underwrite__malloc_wchar_t_cpy_22_goodG2B2Source(wchar_t * data);

static void goodG2B2()
{
    wchar_t * data;
    data = NULL;
    CWE124_Buffer_Underwrite__malloc_wchar_t_cpy_22_goodG2B2Global = 1; /* true */
    data = CWE124_Buffer_Underwrite__malloc_wchar_t_cpy_22_goodG2B2Source(data);
    {
        wchar_t source[100];
        wmemset(source, L'C', 100-1); /* fill with 'C's */
        source[100-1] = L'\0'; /* null terminate */
        /* POTENTIAL FLAW: Possibly copying data to memory before the destination buffer */
        wcscpy(data, source);
        printWLine(data);
        /* INCIDENTAL CWE-401: Memory Leak - data may not point to location
         * returned by malloc() so can't safely call free() on it */
    }
}

void CWE124_Buffer_Underwrite__malloc_wchar_t_cpy_22_good()
{
    goodG2B1();
    goodG2B2();
}

#endif /* OMITGOOD */

/* Below is the main(). It is only used when building this testcase on
 * its own for testing or for building a binary to use in testing binary
 * analysis tools. It is not used when compiling all the testcases as one
 * application, which is how source code analysis tools are tested.
 */

#ifdef INCLUDEMAIN

int main(int argc, char * argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
    printLine("Calling good()...");
    CWE124_Buffer_Underwrite__malloc_wchar_t_cpy_22_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE124_Buffer_Underwrite__malloc_wchar_t_cpy_22_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
