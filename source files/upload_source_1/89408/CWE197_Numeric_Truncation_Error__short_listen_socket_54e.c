/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE197_Numeric_Truncation_Error__short_listen_socket_54e.c
Label Definition File: CWE197_Numeric_Truncation_Error__short.label.xml
Template File: sources-sink-54e.tmpl.c
*/
/*
 * @description
 * CWE: 197 Numeric Truncation Error
 * BadSource: listen_socket Read data using a listen socket (server side)
 * GoodSource: Less than CHAR_MAX
 * Sink:
 *    BadSink : Convert data to a char
 * Flow Variant: 54 Data flow: data passed as an argument from one function through three others to a fifth; all five functions are in different source files
 *
 * */

#include "std_testcase.h"

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
/* Must be at least 8 for atoi() to work properly */
#define CHAR_ARRAY_SIZE 8

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

#ifndef OMITBAD

void CWE197_Numeric_Truncation_Error__short_listen_socket_54e_badSink(short data)
{
    {
        /* POTENTIAL FLAW: Convert data to a char, possibly causing a truncation error */
        char charData = (char)data;
        printHexCharLine(charData);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE197_Numeric_Truncation_Error__short_listen_socket_54e_goodG2BSink(short data)
{
    {
        /* POTENTIAL FLAW: Convert data to a char, possibly causing a truncation error */
        char charData = (char)data;
        printHexCharLine(charData);
    }
}

#endif /* OMITGOOD */
