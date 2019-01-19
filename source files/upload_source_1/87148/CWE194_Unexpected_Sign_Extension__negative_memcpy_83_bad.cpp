/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE194_Unexpected_Sign_Extension__negative_memcpy_83_bad.cpp
Label Definition File: CWE194_Unexpected_Sign_Extension.label.xml
Template File: sources-sink-83_bad.tmpl.cpp
*/
/*
 * @description
 * CWE: 194 Unexpected Sign Extension
 * BadSource: negative Set data to a fixed negative number
 * GoodSource: Positive integer
 * Sinks: memcpy
 *    BadSink : Copy strings using memcpy() with the length of data
 * Flow Variant: 83 Data flow: data passed to class constructor and destructor by declaring the class object on the stack
 *
 * */
#ifndef OMITBAD

#include "std_testcase.h"
#include "CWE194_Unexpected_Sign_Extension__negative_memcpy_83.h"

namespace CWE194_Unexpected_Sign_Extension__negative_memcpy_83
{
CWE194_Unexpected_Sign_Extension__negative_memcpy_83_bad::CWE194_Unexpected_Sign_Extension__negative_memcpy_83_bad(short dataCopy)
{
    data = dataCopy;
    /* FLAW: Use a negative number */
    data = -1;
}

CWE194_Unexpected_Sign_Extension__negative_memcpy_83_bad::~CWE194_Unexpected_Sign_Extension__negative_memcpy_83_bad()
{
    {
        char source[100];
        char dest[100] = "";
        memset(source, 'A', 100-1);
        source[100-1] = '\0';
        if (data < 100)
        {
            /* POTENTIAL FLAW: data is interpreted as an unsigned int - if its value is negative,
             * the sign extension could result in a very large number */
            memcpy(dest, source, data);
            dest[data] = '\0'; /* NULL terminate */
        }
        printLine(dest);
    }
}
}
#endif /* OMITBAD */
