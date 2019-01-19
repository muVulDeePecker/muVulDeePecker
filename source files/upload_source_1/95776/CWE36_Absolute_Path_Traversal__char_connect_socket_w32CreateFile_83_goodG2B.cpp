/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE36_Absolute_Path_Traversal__char_connect_socket_w32CreateFile_83_goodG2B.cpp
Label Definition File: CWE36_Absolute_Path_Traversal.label.xml
Template File: sources-sink-83_goodG2B.tmpl.cpp
*/
/*
 * @description
 * CWE: 36 Absolute Path Traversal
 * BadSource: connect_socket Read data using a connect socket (client side)
 * GoodSource: Full path and file name
 * Sinks: w32CreateFile
 *    BadSink : Open the file named in data using CreateFile()
 * Flow Variant: 83 Data flow: data passed to class constructor and destructor by declaring the class object on the stack
 *
 * */
#ifndef OMITGOOD

#include "std_testcase.h"
#include "CWE36_Absolute_Path_Traversal__char_connect_socket_w32CreateFile_83.h"

#include <windows.h>

namespace CWE36_Absolute_Path_Traversal__char_connect_socket_w32CreateFile_83
{
CWE36_Absolute_Path_Traversal__char_connect_socket_w32CreateFile_83_goodG2B::CWE36_Absolute_Path_Traversal__char_connect_socket_w32CreateFile_83_goodG2B(char * dataCopy)
{
    data = dataCopy;
#ifdef _WIN32
    /* FIX: Use a fixed, full path and file name */
    strcat(data, "c:\\temp\\file.txt");
#else
    /* FIX: Use a fixed, full path and file name */
    strcat(data, "/tmp/file.txt");
#endif
}

CWE36_Absolute_Path_Traversal__char_connect_socket_w32CreateFile_83_goodG2B::~CWE36_Absolute_Path_Traversal__char_connect_socket_w32CreateFile_83_goodG2B()
{
    {
        HANDLE hFile;
        /* POTENTIAL FLAW: Possibly creating and opening a file without validating the file name or path */
        hFile = CreateFileA(data,
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
