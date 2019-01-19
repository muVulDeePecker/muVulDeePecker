/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE665_Improper_Initialization__wchar_t_ncat_84_goodG2B.cpp
Label Definition File: CWE665_Improper_Initialization.label.xml
Template File: sources-sink-84_goodG2B.tmpl.cpp
*/
/*
 * @description
 * CWE: 665 Improper Initialization
 * BadSource:  Do not initialize data properly
 * GoodSource: Initialize data
 * Sinks: ncat
 *    BadSink : Copy string to data using wcsncat
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */
#ifndef OMITGOOD

#include "std_testcase.h"
#include "CWE665_Improper_Initialization__wchar_t_ncat_84.h"

namespace CWE665_Improper_Initialization__wchar_t_ncat_84
{
CWE665_Improper_Initialization__wchar_t_ncat_84_goodG2B::CWE665_Improper_Initialization__wchar_t_ncat_84_goodG2B(wchar_t * dataCopy)
{
    data = dataCopy;
    /* FIX: Properly initialize data */
    data[0] = L'\0'; /* null terminate */
}

CWE665_Improper_Initialization__wchar_t_ncat_84_goodG2B::~CWE665_Improper_Initialization__wchar_t_ncat_84_goodG2B()
{
    {
        size_t sourceLen;
        wchar_t source[100];
        wmemset(source, L'C', 100-1); /* fill with L'C's */
        source[100-1] = L'\0'; /* null terminate */
        sourceLen = wcslen(source);
        /* POTENTIAL FLAW: If data is not initialized properly, wcsncat() may not function correctly */
        wcsncat(data, source, sourceLen);
        printWLine(data);
    }
}
}
#endif /* OMITGOOD */
