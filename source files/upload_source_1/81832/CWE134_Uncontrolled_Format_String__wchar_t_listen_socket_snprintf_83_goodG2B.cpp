/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_snprintf_83_goodG2B.cpp
Label Definition File: CWE134_Uncontrolled_Format_String.label.xml
Template File: sources-sinks-83_goodG2B.tmpl.cpp
*/
/*
 * @description
 * CWE: 134 Uncontrolled Format String
 * BadSource: listen_socket Read data using a listen socket (server side)
 * GoodSource: Copy a fixed string into data
 * Sinks: snprintf
 *    GoodSink: snwprintf with "%s" as the third argument and data as the fourth
 *    BadSink : snwprintf with data as the third argument
 * Flow Variant: 83 Data flow: data passed to class constructor and destructor by declaring the class object on the stack
 *
 * */
#ifndef OMITGOOD

#include "std_testcase.h"
#include "CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_snprintf_83.h"

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <direct.h>
#pragma comment(lib, "ws2_32") /* include ws2_32.lib when linking */
#define CLOSE_SOCKET closesocket
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define CLOSE_SOCKET close
#define SOCKET int
#endif

#define TCP_PORT 27015
#define LISTEN_BACKLOG 5

#ifdef _WIN32
#define SNPRINTF _snwprintf
#else
#define SNPRINTF snprintf
#endif

namespace CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_snprintf_83
{
CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_snprintf_83_goodG2B::CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_snprintf_83_goodG2B(wchar_t * dataCopy)
{
    data = dataCopy;
    /* FIX: Use a fixed string that does not contain a format specifier */
    wcscpy(data, L"fixedstringtest");
}

CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_snprintf_83_goodG2B::~CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_snprintf_83_goodG2B()
{
    {
        wchar_t dest[100] = L"";
        /* POTENTIAL FLAW: Do not specify the format allowing a possible format string vulnerability */
        SNPRINTF(dest, 100-1, data);
        printWLine(dest);
    }
}
}
#endif /* OMITGOOD */
