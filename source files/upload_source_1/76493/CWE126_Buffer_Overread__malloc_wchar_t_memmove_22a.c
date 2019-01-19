/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE126_Buffer_Overread__malloc_wchar_t_memmove_22a.c
Label Definition File: CWE126_Buffer_Overread__malloc.label.xml
Template File: sources-sink-22a.tmpl.c
*/
/*
 * @description
 * CWE: 126 Buffer Over-read
 * BadSource:  Use a small buffer
 * GoodSource: Use a large buffer
 * Sink: memmove
 *    BadSink : Copy data to string using memmove
 * Flow Variant: 22 Control flow: Flow controlled by value of a global variable. Sink functions are in a separate file from sources.
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

/* The global variable below is used to drive control flow in the source function */
int CWE126_Buffer_Overread__malloc_wchar_t_memmove_22_badGlobal = 0;

wchar_t * CWE126_Buffer_Overread__malloc_wchar_t_memmove_22_badSource(wchar_t * data);

void CWE126_Buffer_Overread__malloc_wchar_t_memmove_22_bad()
{
    wchar_t * data;
    data = NULL;
    CWE126_Buffer_Overread__malloc_wchar_t_memmove_22_badGlobal = 1; /* true */
    data = CWE126_Buffer_Overread__malloc_wchar_t_memmove_22_badSource(data);
    {
        wchar_t dest[100];
        wmemset(dest, L'C', 100-1);
        dest[100-1] = L'\0'; /* null terminate */
        /* POTENTIAL FLAW: using memmove with the length of the dest where data
         * could be smaller than dest causing buffer overread */
        memmove(dest, data, wcslen(dest)*sizeof(wchar_t));
        dest[100-1] = L'\0';
        printWLine(dest);
        free(data);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* The global variables below are used to drive control flow in the source functions. */
int CWE126_Buffer_Overread__malloc_wchar_t_memmove_22_goodG2B1Global = 0;
int CWE126_Buffer_Overread__malloc_wchar_t_memmove_22_goodG2B2Global = 0;

/* goodG2B1() - use goodsource and badsink by setting the static variable to false instead of true */
wchar_t * CWE126_Buffer_Overread__malloc_wchar_t_memmove_22_goodG2B1Source(wchar_t * data);

static void goodG2B1()
{
    wchar_t * data;
    data = NULL;
    CWE126_Buffer_Overread__malloc_wchar_t_memmove_22_goodG2B1Global = 0; /* false */
    data = CWE126_Buffer_Overread__malloc_wchar_t_memmove_22_goodG2B1Source(data);
    {
        wchar_t dest[100];
        wmemset(dest, L'C', 100-1);
        dest[100-1] = L'\0'; /* null terminate */
        /* POTENTIAL FLAW: using memmove with the length of the dest where data
         * could be smaller than dest causing buffer overread */
        memmove(dest, data, wcslen(dest)*sizeof(wchar_t));
        dest[100-1] = L'\0';
        printWLine(dest);
        free(data);
    }
}

/* goodG2B2() - use goodsource and badsink by reversing the blocks in the if in the source function */
wchar_t * CWE126_Buffer_Overread__malloc_wchar_t_memmove_22_goodG2B2Source(wchar_t * data);

static void goodG2B2()
{
    wchar_t * data;
    data = NULL;
    CWE126_Buffer_Overread__malloc_wchar_t_memmove_22_goodG2B2Global = 1; /* true */
    data = CWE126_Buffer_Overread__malloc_wchar_t_memmove_22_goodG2B2Source(data);
    {
        wchar_t dest[100];
        wmemset(dest, L'C', 100-1);
        dest[100-1] = L'\0'; /* null terminate */
        /* POTENTIAL FLAW: using memmove with the length of the dest where data
         * could be smaller than dest causing buffer overread */
        memmove(dest, data, wcslen(dest)*sizeof(wchar_t));
        dest[100-1] = L'\0';
        printWLine(dest);
        free(data);
    }
}

void CWE126_Buffer_Overread__malloc_wchar_t_memmove_22_good()
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
    CWE126_Buffer_Overread__malloc_wchar_t_memmove_22_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE126_Buffer_Overread__malloc_wchar_t_memmove_22_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
