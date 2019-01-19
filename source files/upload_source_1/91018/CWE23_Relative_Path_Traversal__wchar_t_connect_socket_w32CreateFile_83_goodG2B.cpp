/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE23_Relative_Path_Traversal__wchar_t_connect_socket_w32CreateFile_83_goodG2B.cpp
Label Definition File: CWE23_Relative_Path_Traversal.label.xml
Template File: sources-sink-83_goodG2B.tmpl.cpp
*/
/*
 * @description
 * CWE: 23 Relative Path Traversal
 * BadSource: connect_socket Read data using a connect socket (client side)
 * GoodSource: Use a fixed file name
 * Sinks: w32CreateFile
 *    BadSink : Open the file named in data using CreateFile()
 * Flow Variant: 83 Data flow: data passed to class constructor and destructor by declaring the class object on the stack
 *
 * */
#ifndef OMITGOOD

#include "std_testcase.h"
#include "CWE23_Relative_Path_Traversal__wchar_t_connect_socket_w32CreateFile_83.h"

#include <windows.h>

namespace CWE23_Relative_Path_Traversal__wchar_t_connect_socket_w32CreateFile_83
{
CWE23_Relative_Path_Traversal__wchar_t_connect_socket_w32CreateFile_83_goodG2B::CWE23_Relative_Path_Traversal__wchar_t_connect_socket_w32CreateFile_83_goodG2B(wchar_t * dataCopy)
{
    data = dataCopy;
    /* FIX: Use a fixed file name */
    wcscat(data, L"file.txt");
}

CWE23_Relative_Path_Traversal__wchar_t_connect_socket_w32CreateFile_83_goodG2B::~CWE23_Relative_Path_Traversal__wchar_t_connect_socket_w32CreateFile_83_goodG2B()
{
    {
        HANDLE hFile;
        /* POTENTIAL FLAW: Possibly creating and opening a file without validating the file name or path */
        hFile = CreateFileW(data,
                            (GENERIC_WRITE|GENERIC_READ),
                            0,
                            NULL,
                            OPEN_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL,
                            NULL);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            CloseHandle(hFile);
        }
    }
}
}
#endif /* OMITGOOD */
