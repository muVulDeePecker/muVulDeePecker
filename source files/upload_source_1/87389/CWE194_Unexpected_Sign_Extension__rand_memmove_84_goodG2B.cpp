/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE194_Unexpected_Sign_Extension__rand_memmove_84_goodG2B.cpp
Label Definition File: CWE194_Unexpected_Sign_Extension.label.xml
Template File: sources-sink-84_goodG2B.tmpl.cpp
*/
/*
 * @description
 * CWE: 194 Unexpected Sign Extension
 * BadSource: rand Set data to result of RAND32(), which could be negative
 * GoodSource: Positive integer
 * Sinks: memmove
 *    BadSink : Copy strings using memmove() with the length of data
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */
#ifndef OMITGOOD

#include "std_testcase.h"
#include "CWE194_Unexpected_Sign_Extension__rand_memmove_84.h"

namespace CWE194_Unexpected_Sign_Extension__rand_memmove_84
{
CWE194_Unexpected_Sign_Extension__rand_memmove_84_goodG2B::CWE194_Unexpected_Sign_Extension__rand_memmove_84_goodG2B(short dataCopy)
{
    data = dataCopy;
    /* FIX: Use a positive integer less than &InitialDataSize&*/
    data = 100-1;
}

CWE194_Unexpected_Sign_Extension__rand_memmove_84_goodG2B::~CWE194_Unexpected_Sign_Extension__rand_memmove_84_goodG2B()
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
            memmove(dest, source, data);
            dest[data] = '\0'; /* NULL terminate */
        }
        printLine(dest);
    }
}
}
#endif /* OMITGOOD */
