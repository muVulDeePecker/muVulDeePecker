/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_snprintf_84_bad.cpp
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__c_CWE805.string.label.xml
Template File: sources-sink-84_bad.tmpl.cpp
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Allocate using malloc() and set data pointer to a small buffer
 * GoodSource: Allocate using malloc() and set data pointer to a large buffer
 * Sinks: snprintf
 *    BadSink : Copy string to data using snprintf
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */
#ifndef OMITBAD

#include "std_testcase.h"
#include "CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_snprintf_84.h"

#ifdef _WIN32
#define SNPRINTF _snprintf
#else
#define SNPRINTF snprintf
#endif

namespace CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_snprintf_84
{
CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_snprintf_84_bad::CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_snprintf_84_bad(char * dataCopy)
{
    data = dataCopy;
    /* FLAW: Allocate and point data to a small buffer that is smaller than the large buffer used in the sinks */
    data = (char *)malloc(50*sizeof(char));
    data[0] = '\0'; /* null terminate */
}

CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_snprintf_84_bad::~CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_snprintf_84_bad()
{
    {
        char source[100];
        memset(source, 'C', 100-1); /* fill with 'C's */
        source[100-1] = '\0'; /* null terminate */
        /* POTENTIAL FLAW: Possible buffer overflow if source is larger than data */
        SNPRINTF(data, 100, "%s", source);
        printLine(data);
        free(data);
    }
}
}
#endif /* OMITBAD */
