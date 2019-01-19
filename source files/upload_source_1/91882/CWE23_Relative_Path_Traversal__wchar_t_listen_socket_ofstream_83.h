/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE23_Relative_Path_Traversal__wchar_t_listen_socket_ofstream_83.h
Label Definition File: CWE23_Relative_Path_Traversal.label.xml
Template File: sources-sink-83.tmpl.h
*/
/*
 * @description
 * CWE: 23 Relative Path Traversal
 * BadSource: listen_socket Read data using a listen socket (server side)
 * GoodSource: Use a fixed file name
 * Sinks: ofstream
 *    BadSink : Open the file named in data using ofstream::open()
 * Flow Variant: 83 Data flow: data passed to class constructor and destructor by declaring the class object on the stack
 *
 * */

#include "std_testcase.h"

#ifdef _WIN32
#define BASEPATH L"c:\\temp\\"
#else
#include <wchar.h>
#define BASEPATH L"/tmp/"
#endif

namespace CWE23_Relative_Path_Traversal__wchar_t_listen_socket_ofstream_83
{

#ifndef OMITBAD

class CWE23_Relative_Path_Traversal__wchar_t_listen_socket_ofstream_83_bad
{
public:
    CWE23_Relative_Path_Traversal__wchar_t_listen_socket_ofstream_83_bad(wchar_t * dataCopy);
    ~CWE23_Relative_Path_Traversal__wchar_t_listen_socket_ofstream_83_bad();

private:
    wchar_t * data;
};

#endif /* OMITBAD */

#ifndef OMITGOOD

class CWE23_Relative_Path_Traversal__wchar_t_listen_socket_ofstream_83_goodG2B
{
public:
    CWE23_Relative_Path_Traversal__wchar_t_listen_socket_ofstream_83_goodG2B(wchar_t * dataCopy);
    ~CWE23_Relative_Path_Traversal__wchar_t_listen_socket_ofstream_83_goodG2B();

private:
    wchar_t * data;
};

#endif /* OMITGOOD */

}
