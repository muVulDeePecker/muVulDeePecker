/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE197_Numeric_Truncation_Error__int_connect_socket_to_char_81.h
Label Definition File: CWE197_Numeric_Truncation_Error__int.label.xml
Template File: sources-sink-81.tmpl.h
*/
/*
 * @description
 * CWE: 197 Numeric Truncation Error
 * BadSource: connect_socket Read data using a connect socket (client side)
 * GoodSource: Less than CHAR_MAX
 * Sinks: to_char
 *    BadSink : Convert data to a char
 * Flow Variant: 81 Data flow: data passed in a parameter to an virtual method called via a reference
 *
 * */

#include "std_testcase.h"

namespace CWE197_Numeric_Truncation_Error__int_connect_socket_to_char_81
{

class CWE197_Numeric_Truncation_Error__int_connect_socket_to_char_81_base
{
public:
    /* pure virtual function */
    virtual void action(int data) const = 0;
};

#ifndef OMITBAD

class CWE197_Numeric_Truncation_Error__int_connect_socket_to_char_81_bad : public CWE197_Numeric_Truncation_Error__int_connect_socket_to_char_81_base
{
public:
    void action(int data) const;
};

#endif /* OMITBAD */

#ifndef OMITGOOD

class CWE197_Numeric_Truncation_Error__int_connect_socket_to_char_81_goodG2B : public CWE197_Numeric_Truncation_Error__int_connect_socket_to_char_81_base
{
public:
    void action(int data) const;
};

#endif /* OMITGOOD */

}
