/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__src_wchar_t_declare_cat_66b.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__src.label.xml
Template File: sources-sink-66b.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * BadSource:  Initialize data as a large string
 * GoodSource: Initialize data as a small string
 * Sinks: cat
 *    BadSink : Copy data to string using wcscat
 * Flow Variant: 66 Data flow: data passed in an array from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

void CWE121_Stack_Based_Buffer_Overflow__src_wchar_t_declare_cat_66b_badSink(wchar_t * dataArray[])
{
    /* copy data out of dataArray */
    wchar_t * data = dataArray[2];
    {
        wchar_t dest[50] = L"";
        /* POTENTIAL FLAW: Possible buffer overflow if data is larger than sizeof(dest)-wcslen(dest)*/
        wcscat(dest, data);
        printWLine(data);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE121_Stack_Based_Buffer_Overflow__src_wchar_t_declare_cat_66b_goodG2BSink(wchar_t * dataArray[])
{
    wchar_t * data = dataArray[2];
    {
        wchar_t dest[50] = L"";
        /* POTENTIAL FLAW: Possible buffer overflow if data is larger than sizeof(dest)-wcslen(dest)*/
        wcscat(dest, data);
        printWLine(data);
    }
}

#endif /* OMITGOOD */
