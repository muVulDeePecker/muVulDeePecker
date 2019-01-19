/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_memcpy_84.h
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__c_CWE193.label.xml
Template File: sources-sink-84.tmpl.h
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Allocate memory for a string, but do not allocate space for NULL terminator
 * GoodSource: Allocate enough memory for a string and the NULL terminator
 * Sinks: memcpy
 *    BadSink : Copy string to data using memcpy()
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */

#include "std_testcase.h"

#ifndef _WIN32
#include <wchar.h>
#endif

/* MAINTENANCE NOTE: The length of this string should equal the 10 */
#define SRC_STRING "AAAAAAAAAA"

namespace CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_memcpy_84
{

#ifndef OMITBAD

class CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_memcpy_84_bad
{
public:
    CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_memcpy_84_bad(char * dataCopy);
    ~CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_memcpy_84_bad();

private:
    char * data;
};

#endif /* OMITBAD */

#ifndef OMITGOOD

class CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_memcpy_84_goodG2B
{
public:
    CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_memcpy_84_goodG2B(char * dataCopy);
    ~CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_memcpy_84_goodG2B();

private:
    char * data;
};

#endif /* OMITGOOD */

}
