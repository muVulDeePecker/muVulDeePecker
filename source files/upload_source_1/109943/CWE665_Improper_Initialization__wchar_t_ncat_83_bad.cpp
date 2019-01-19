/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE665_Improper_Initialization__wchar_t_ncat_83_bad.cpp
Label Definition File: CWE665_Improper_Initialization.label.xml
Template File: sources-sink-83_bad.tmpl.cpp
*/
/*
 * @description
 * CWE: 665 Improper Initialization
 * BadSource:  Do not initialize data properly
 * GoodSource: Initialize data
 * Sinks: ncat
 *    BadSink : Copy string to data using wcsncat
 * Flow Variant: 83 Data flow: data passed to class constructor and destructor by declaring the class object on the stack
 *
 * */
#ifndef OMITBAD

#include "std_testcase.h"
#include "CWE665_Improper_Initialization__wchar_t_ncat_83.h"

namespace CWE665_Improper_Initialization__wchar_t_ncat_83
{
CWE665_Improper_Initialization__wchar_t_ncat_83_bad::CWE665_Improper_Initialization__wchar_t_ncat_83_bad(wchar_t * dataCopy)
{
    data = dataCopy;
    /* FLAW: Do not initialize data */
    ; /* empty statement needed for some flow variants */
}

CWE665_Improper_Initialization__wchar_t_ncat_83_bad::~CWE665_Improper_Initialization__wchar_t_ncat_83_bad()
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
#endif /* OMITBAD */
