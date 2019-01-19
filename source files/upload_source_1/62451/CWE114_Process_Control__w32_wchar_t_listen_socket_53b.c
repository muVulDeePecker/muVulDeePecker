/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE114_Process_Control__w32_wchar_t_listen_socket_53b.c
Label Definition File: CWE114_Process_Control__w32.label.xml
Template File: sources-sink-53b.tmpl.c
*/
/*
 * @description
 * CWE: 114 Process Control
 * BadSource: listen_socket Read data using a listen socket (server side)
 * GoodSource: Hard code the full pathname to the library
 * Sink:
 *    BadSink : Load a dynamic link library
 * Flow Variant: 53 Data flow: data passed as an argument from one function through two others to a fourth; all four functions are in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

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


/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

#ifndef OMITBAD

/* bad function declaration */
void CWE114_Process_Control__w32_wchar_t_listen_socket_53c_badSink(wchar_t * data);

void CWE114_Process_Control__w32_wchar_t_listen_socket_53b_badSink(wchar_t * data)
{
    CWE114_Process_Control__w32_wchar_t_listen_socket_53c_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good function declaration */
void CWE114_Process_Control__w32_wchar_t_listen_socket_53c_goodG2BSink(wchar_t * data);

/* goodG2B uses the GoodSource with the BadSink */
void CWE114_Process_Control__w32_wchar_t_listen_socket_53b_goodG2BSink(wchar_t * data)
{
    CWE114_Process_Control__w32_wchar_t_listen_socket_53c_goodG2BSink(data);
}

#endif /* OMITGOOD */
