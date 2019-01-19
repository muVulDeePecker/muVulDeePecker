/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__placement_new_82.h
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__placement_new.label.xml
Template File: sources-sinks-82.tmpl.h
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Initialize data to a small buffer
 * GoodSource: Initialize data to a buffer large enough to hold a TwoIntsClass
 * Sinks:
 *    GoodSink: Allocate a new class using placement new and a buffer that is large enough to hold the class
 *    BadSink : Allocate a new class using placement new and a buffer that is too small
 * Flow Variant: 82 Data flow: data passed in a parameter to an virtual method called via a pointer
 *
 * */

#include "std_testcase.h"

namespace CWE122_Heap_Based_Buffer_Overflow__placement_new_82
{

class CWE122_Heap_Based_Buffer_Overflow__placement_new_82_base
{
public:
    /* pure virtual function */
    virtual void action(char * data) = 0;
};

#ifndef OMITBAD

class CWE122_Heap_Based_Buffer_Overflow__placement_new_82_bad : public CWE122_Heap_Based_Buffer_Overflow__placement_new_82_base
{
public:
    void action(char * data);
};

#endif /* OMITBAD */

#ifndef OMITGOOD

class CWE122_Heap_Based_Buffer_Overflow__placement_new_82_goodG2B : public CWE122_Heap_Based_Buffer_Overflow__placement_new_82_base
{
public:
    void action(char * data);
};

class CWE122_Heap_Based_Buffer_Overflow__placement_new_82_goodB2G : public CWE122_Heap_Based_Buffer_Overflow__placement_new_82_base
{
public:
    void action(char * data);
};

#endif /* OMITGOOD */

}
