/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_83.h
Label Definition File: CWE427_Uncontrolled_Search_Path_Element.label.xml
Template File: sources-sink-83.tmpl.h
*/
/*
 * @description
 * CWE: 427 Uncontrolled Search Path Element
 * BadSource: listen_socket Read data using a listen socket (server side)
 * GoodSource: Use a hardcoded path
 * Sinks:
 *    BadSink : Set the environment variable
 * Flow Variant: 83 Data flow: data passed to class constructor and destructor by declaring the class object on the stack
 *
 * */

#include "std_testcase.h"

#include <wchar.h>
#ifdef _WIN32
#define NEW_PATH L"%SystemRoot%\\system32"
#define PUTENV _wputenv
#else
#define NEW_PATH L"/bin"
#define PUTENV putenv
#endif

namespace CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_83
{

#ifndef OMITBAD

class CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_83_bad
{
public:
    CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_83_bad(wchar_t * dataCopy);
    ~CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_83_bad();

private:
    wchar_t * data;
};

#endif /* OMITBAD */

#ifndef OMITGOOD

class CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_83_goodG2B
{
public:
    CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_83_goodG2B(wchar_t * dataCopy);
    ~CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_83_goodG2B();

private:
    wchar_t * data;
};

#endif /* OMITGOOD */

}
