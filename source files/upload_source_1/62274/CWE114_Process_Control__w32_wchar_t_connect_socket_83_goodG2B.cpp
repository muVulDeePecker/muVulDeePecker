/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE114_Process_Control__w32_wchar_t_connect_socket_83_goodG2B.cpp
Label Definition File: CWE114_Process_Control__w32.label.xml
Template File: sources-sink-83_goodG2B.tmpl.cpp
*/
/*
 * @description
 * CWE: 114 Process Control
 * BadSource: connect_socket Read data using a connect socket (client side)
 * GoodSource: Hard code the full pathname to the library
 * Sinks:
 *    BadSink : Load a dynamic link library
 * Flow Variant: 83 Data flow: data passed to class constructor and destructor by declaring the class object on the stack
 *
 * */
#ifndef OMITGOOD

#include "std_testcase.h"
#include "CWE114_Process_Control__w32_wchar_t_connect_socket_83.h"

#include <windows.h>

namespace CWE114_Process_Control__w32_wchar_t_connect_socket_83
{
CWE114_Process_Control__w32_wchar_t_connect_socket_83_goodG2B::CWE114_Process_Control__w32_wchar_t_connect_socket_83_goodG2B(wchar_t * dataCopy)
{
    data = dataCopy;
    /* FIX: Specify the full pathname for the library */
    wcscpy(data, L"C:\\Windows\\System32\\winsrv.dll");
}

CWE114_Process_Control__w32_wchar_t_connect_socket_83_goodG2B::~CWE114_Process_Control__w32_wchar_t_connect_socket_83_goodG2B()
{
    {
        HMODULE hModule;
        /* POTENTIAL FLAW: If the path to the library is not specified, an attacker may be able to
         * replace his own file with the intended library */
        hModule = LoadLibraryW(data);
        if (hModule != NULL)
        {
            FreeLibrary(hModule);
            printLine("Library loaded and freed successfully");
        }
        else
        {
            printLine("Unable to load library");
        }
    }
}
}
#endif /* OMITGOOD */
