/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE36_Absolute_Path_Traversal__wchar_t_connect_socket_ofstream_84.h
Label Definition File: CWE36_Absolute_Path_Traversal.label.xml
Template File: sources-sink-84.tmpl.h
*/
/*
 * @description
 * CWE: 36 Absolute Path Traversal
 * BadSource: connect_socket Read data using a connect socket (client side)
 * GoodSource: Full path and file name
 * Sinks: ofstream
 *    BadSink : Open the file named in data using ofstream::open()
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */

#include "std_testcase.h"

#ifndef _WIN32
#include <wchar.h>
#endif

namespace CWE36_Absolute_Path_Traversal__wchar_t_connect_socket_ofstream_84
{

#ifndef OMITBAD

class CWE36_Absolute_Path_Traversal__wchar_t_connect_socket_ofstream_84_bad
{
public:
    CWE36_Absolute_Path_Traversal__wchar_t_connect_socket_ofstream_84_bad(wchar_t * dataCopy);
    ~CWE36_Absolute_Path_Traversal__wchar_t_connect_socket_ofstream_84_bad();

private:
    wchar_t * data;
};

#endif /* OMITBAD */

#ifndef OMITGOOD

class CWE36_Absolute_Path_Traversal__wchar_t_connect_socket_ofstream_84_goodG2B
{
public:
    CWE36_Absolute_Path_Traversal__wchar_t_connect_socket_ofstream_84_goodG2B(wchar_t * dataCopy);
    ~CWE36_Absolute_Path_Traversal__wchar_t_connect_socket_ofstream_84_goodG2B();

private:
    wchar_t * data;
};

#endif /* OMITGOOD */

}
