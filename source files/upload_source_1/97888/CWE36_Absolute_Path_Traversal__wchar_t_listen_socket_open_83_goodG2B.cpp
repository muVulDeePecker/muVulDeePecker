/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE36_Absolute_Path_Traversal__wchar_t_listen_socket_open_83_goodG2B.cpp
Label Definition File: CWE36_Absolute_Path_Traversal.label.xml
Template File: sources-sink-83_goodG2B.tmpl.cpp
*/
/*
 * @description
 * CWE: 36 Absolute Path Traversal
 * BadSource: listen_socket Read data using a listen socket (server side)
 * GoodSource: Full path and file name
 * Sinks: open
 *    BadSink : Open the file named in data using open()
 * Flow Variant: 83 Data flow: data passed to class constructor and destructor by declaring the class object on the stack
 *
 * */
#ifndef OMITGOOD

#include "std_testcase.h"
#include "CWE36_Absolute_Path_Traversal__wchar_t_listen_socket_open_83.h"

#ifdef _WIN32
#define OPEN _wopen
#define CLOSE _close
#else
#include <unistd.h>
#define OPEN open
#define CLOSE close
#endif

namespace CWE36_Absolute_Path_Traversal__wchar_t_listen_socket_open_83
{
CWE36_Absolute_Path_Traversal__wchar_t_listen_socket_open_83_goodG2B::CWE36_Absolute_Path_Traversal__wchar_t_listen_socket_open_83_goodG2B(wchar_t * dataCopy)
{
    data = dataCopy;
#ifdef _WIN32
    /* FIX: Use a fixed, full path and file name */
    wcscat(data, L"c:\\temp\\file.txt");
#else
    /* FIX: Use a fixed, full path and file name */
    wcscat(data, L"/tmp/file.txt");
#endif
}

CWE36_Absolute_Path_Traversal__wchar_t_listen_socket_open_83_goodG2B::~CWE36_Absolute_Path_Traversal__wchar_t_listen_socket_open_83_goodG2B()
{
    {
        int fileDesc;
        /* POTENTIAL FLAW: Possibly opening a file without validating the file name or path */
        fileDesc = OPEN(data, O_RDWR|O_CREAT, S_IREAD|S_IWRITE);
        if (fileDesc != -1)
        {
            CLOSE(fileDesc);
        }
    }
}
}
#endif /* OMITGOOD */
