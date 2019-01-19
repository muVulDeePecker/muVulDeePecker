/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__c_CWE129_large_82.h
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__c_CWE129.label.xml
Template File: sources-sinks-82.tmpl.h
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource: large Large index value that is greater than 10-1
 * GoodSource: Larger than zero but less than 10
 * Sinks:
 *    GoodSink: Ensure the array index is valid
 *    BadSink : Improperly check the array index by not checking the upper bound
 * Flow Variant: 82 Data flow: data passed in a parameter to an virtual method called via a pointer
 *
 * */

#include "std_testcase.h"

namespace CWE122_Heap_Based_Buffer_Overflow__c_CWE129_large_82
{

class CWE122_Heap_Based_Buffer_Overflow__c_CWE129_large_82_base
{
public:
    /* pure virtual function */
    virtual void action(int data) = 0;
};

#ifndef OMITBAD

class CWE122_Heap_Based_Buffer_Overflow__c_CWE129_large_82_bad : public CWE122_Heap_Based_Buffer_Overflow__c_CWE129_large_82_base
{
public:
    void action(int data);
};

#endif /* OMITBAD */

#ifndef OMITGOOD

class CWE122_Heap_Based_Buffer_Overflow__c_CWE129_large_82_goodG2B : public CWE122_Heap_Based_Buffer_Overflow__c_CWE129_large_82_base
{
public:
    void action(int data);
};

class CWE122_Heap_Based_Buffer_Overflow__c_CWE129_large_82_goodB2G : public CWE122_Heap_Based_Buffer_Overflow__c_CWE129_large_82_base
{
public:
    void action(int data);
};

#endif /* OMITGOOD */

}
