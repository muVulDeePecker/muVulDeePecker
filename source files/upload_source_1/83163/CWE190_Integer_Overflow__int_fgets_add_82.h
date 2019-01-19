/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE190_Integer_Overflow__int_fgets_add_82.h
Label Definition File: CWE190_Integer_Overflow__int.label.xml
Template File: sources-sinks-82.tmpl.h
*/
/*
 * @description
 * CWE: 190 Integer Overflow
 * BadSource: fgets Read data from the console using fgets()
 * GoodSource: Set data to a small, non-zero number (two)
 * Sinks: add
 *    GoodSink: Ensure there will not be an overflow before adding 1 to data
 *    BadSink : Add 1 to data, which can cause an overflow
 * Flow Variant: 82 Data flow: data passed in a parameter to an virtual method called via a pointer
 *
 * */

#include "std_testcase.h"

namespace CWE190_Integer_Overflow__int_fgets_add_82
{

class CWE190_Integer_Overflow__int_fgets_add_82_base
{
public:
    /* pure virtual function */
    virtual void action(int data) = 0;
};

#ifndef OMITBAD

class CWE190_Integer_Overflow__int_fgets_add_82_bad : public CWE190_Integer_Overflow__int_fgets_add_82_base
{
public:
    void action(int data);
};

#endif /* OMITBAD */

#ifndef OMITGOOD

class CWE190_Integer_Overflow__int_fgets_add_82_goodG2B : public CWE190_Integer_Overflow__int_fgets_add_82_base
{
public:
    void action(int data);
};

class CWE190_Integer_Overflow__int_fgets_add_82_goodB2G : public CWE190_Integer_Overflow__int_fgets_add_82_base
{
public:
    void action(int data);
};

#endif /* OMITGOOD */

}
