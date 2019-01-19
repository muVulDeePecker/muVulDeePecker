/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_52b.c
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__c_CWE193.label.xml
Template File: sources-sink-52b.tmpl.c
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Allocate memory for a string, but do not allocate space for NULL terminator
 * GoodSource: Allocate enough memory for a string and the NULL terminator
 * Sink: cpy
 *    BadSink : Copy string to data using strcpy()
 * Flow Variant: 52 Data flow: data passed as an argument from one function to another to another in three different source files
 *
 * */

#include "std_testcase.h"

#ifndef _WIN32
#include <wchar.h>
#endif

/* MAINTENANCE NOTE: The length of this string should equal the 10 */
#define SRC_STRING "AAAAAAAAAA"

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

#ifndef OMITBAD

/* bad function declaration */
void CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_52c_badSink(char * data);

void CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_52b_badSink(char * data)
{
    CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_52c_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good function declaration */
void CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_52c_goodG2BSink(char * data);

/* goodG2B uses the GoodSource with the BadSink */
void CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_52b_goodG2BSink(char * data)
{
    CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_52c_goodG2BSink(data);
}

#endif /* OMITGOOD */
