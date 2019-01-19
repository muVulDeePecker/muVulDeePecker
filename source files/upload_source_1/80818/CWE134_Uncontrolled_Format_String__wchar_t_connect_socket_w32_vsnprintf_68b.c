/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE134_Uncontrolled_Format_String__wchar_t_connect_socket_w32_vsnprintf_68b.c
Label Definition File: CWE134_Uncontrolled_Format_String.vasinks.label.xml
Template File: sources-vasinks-68b.tmpl.c
*/
/*
 * @description
 * CWE: 134 Uncontrolled Format String
 * BadSource: connect_socket Read data using a connect socket (client side)
 * GoodSource: Copy a fixed string into data
 * Sinks: w32_vsnprintf
 *    GoodSink: _vsnwprintf with a format string
 *    BadSink : _vsnwprintf without a format string
 * Flow Variant: 68 Data flow: data passed as a global variable from one function to another in different source files
 *
 * */

#include <stdarg.h>
#include "std_testcase.h"

#ifndef _WIN32
#include <wchar.h>
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <direct.h>
#pragma comment(lib, "ws2_32") /* include ws2_32.lib when linking */
#define CLOSE_SOCKET closesocket
#else /* NOT _WIN32 */
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
#define IP_ADDRESS "127.0.0.1"

extern wchar_t * CWE134_Uncontrolled_Format_String__wchar_t_connect_socket_w32_vsnprintf_68_badData;
extern wchar_t * CWE134_Uncontrolled_Format_String__wchar_t_connect_socket_w32_vsnprintf_68_goodG2BData;
extern wchar_t * CWE134_Uncontrolled_Format_String__wchar_t_connect_socket_w32_vsnprintf_68_goodB2GData;

#ifndef OMITBAD

static void badVaSink(wchar_t * data, ...)
{
    {
        wchar_t dest[100] = L"";
        va_list args;
        va_start(args, data);
        /* POTENTIAL FLAW: Do not specify the format allowing a possible format string vulnerability */
        _vsnwprintf(dest, 100-1, data, args);
        va_end(args);
        printWLine(dest);
    }
}

void CWE134_Uncontrolled_Format_String__wchar_t_connect_socket_w32_vsnprintf_68b_badSink()
{
    wchar_t * data = CWE134_Uncontrolled_Format_String__wchar_t_connect_socket_w32_vsnprintf_68_badData;
    badVaSink(data, data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2BVaSink(wchar_t * data, ...)
{
    {
        wchar_t dest[100] = L"";
        va_list args;
        va_start(args, data);
        /* POTENTIAL FLAW: Do not specify the format allowing a possible format string vulnerability */
        _vsnwprintf(dest, 100-1, data, args);
        va_end(args);
        printWLine(dest);
    }
}

void CWE134_Uncontrolled_Format_String__wchar_t_connect_socket_w32_vsnprintf_68b_goodG2BSink()
{
    wchar_t * data = CWE134_Uncontrolled_Format_String__wchar_t_connect_socket_w32_vsnprintf_68_goodG2BData;
    goodG2BVaSink(data, data);
}

/* goodB2G uses the BadSource with the GoodSink */
static void goodB2GVaSink(wchar_t * data, ...)
{
    {
        wchar_t dest[100] = L"";
        va_list args;
        va_start(args, data);
        /* FIX: Specify the format disallowing a format string vulnerability */
        _vsnwprintf(dest, 100-1, L"%s", args);
        va_end(args);
        printWLine(dest);
    }
}

void CWE134_Uncontrolled_Format_String__wchar_t_connect_socket_w32_vsnprintf_68b_goodB2GSink()
{
    wchar_t * data = CWE134_Uncontrolled_Format_String__wchar_t_connect_socket_w32_vsnprintf_68_goodB2GData;
    goodB2GVaSink(data, data);
}

#endif /* OMITGOOD */
