/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__dest_char_alloca_cat_82_goodG2B.cpp
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__dest.label.xml
Template File: sources-sink-82_goodG2B.tmpl.cpp
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * BadSource:  Set data pointer to the bad buffer
 * GoodSource: Set data pointer to the good buffer
 * Sinks: cat
 *    BadSink : Copy string to data using strcat
 * Flow Variant: 82 Data flow: data passed in a parameter to an virtual method called via a pointer
 *
 * */
#ifndef OMITGOOD

#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__dest_char_alloca_cat_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__dest_char_alloca_cat_82
{

void CWE121_Stack_Based_Buffer_Overflow__dest_char_alloca_cat_82_goodG2B::action(char * data)
{
    {
        char source[100];
        memset(source, 'C', 100-1); /* fill with 'C's */
        source[100-1] = '\0'; /* null terminate */
        /* POTENTIAL FLAW: Possible buffer overflow if the sizeof(data)-strlen(data) is less than the length of source */
        strcat(data, source);
        printLine(data);
    }
}

}
#endif /* OMITGOOD */
