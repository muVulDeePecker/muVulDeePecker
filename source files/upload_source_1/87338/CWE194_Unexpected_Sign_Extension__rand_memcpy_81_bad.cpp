/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE194_Unexpected_Sign_Extension__rand_memcpy_81_bad.cpp
Label Definition File: CWE194_Unexpected_Sign_Extension.label.xml
Template File: sources-sink-81_bad.tmpl.cpp
*/
/*
 * @description
 * CWE: 194 Unexpected Sign Extension
 * BadSource: rand Set data to result of RAND32(), which could be negative
 * GoodSource: Positive integer
 * Sinks: memcpy
 *    BadSink : Copy strings using memcpy() with the length of data
 * Flow Variant: 81 Data flow: data passed in a parameter to an virtual method called via a reference
 *
 * */
#ifndef OMITBAD

#include "std_testcase.h"
#include "CWE194_Unexpected_Sign_Extension__rand_memcpy_81.h"

namespace CWE194_Unexpected_Sign_Extension__rand_memcpy_81
{

void CWE194_Unexpected_Sign_Extension__rand_memcpy_81_bad::action(short data) const
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
