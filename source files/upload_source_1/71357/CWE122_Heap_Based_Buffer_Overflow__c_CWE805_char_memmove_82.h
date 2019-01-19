/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_82.h
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__c_CWE805.string.label.xml
Template File: sources-sink-82.tmpl.h
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Allocate using malloc() and set data pointer to a small buffer
 * GoodSource: Allocate using malloc() and set data pointer to a large buffer
 *    BadSink : Copy string to data using memmove
 * Flow Variant: 82 Data flow: data passed in a parameter to an virtual method called via a pointer
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

namespace CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_82
{

class CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_82_base
{
public:
    /* pure virtual function */
    virtual void action(char * data) = 0;
};

#ifndef OMITBAD

class CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_82_bad : public CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_82_base
{
public:
    void action(char * data);
};

#endif /* OMITBAD */

#ifndef OMITGOOD

class CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_82_goodG2B : public CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_82_base
{
public:
    void action(char * data);
};

#endif /* OMITGOOD */

}
