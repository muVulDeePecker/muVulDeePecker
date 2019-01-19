/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE114_Process_Control__w32_char_listen_socket_54d.c
Label Definition File: CWE114_Process_Control__w32.label.xml
Template File: sources-sink-54d.tmpl.c
*/
/*
 * @description
 * CWE: 114 Process Control
 * BadSource: listen_socket Read data using a listen socket (server side)
 * GoodSource: Hard code the full pathname to the library
 * Sink:
 *    BadSink : Load a dynamic link library
 * Flow Variant: 54 Data flow: data passed as an argument from one function through three others to a fifth; all five functions are in different source files
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
void CWE114_Process_Control__w32_char_listen_socket_54e_badSink(char * data);

void CWE114_Process_Control__w32_char_listen_socket_54d_badSink(char * data)
{
    CWE114_Process_Control__w32_char_listen_socket_54e_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good function declaration */
void CWE114_Process_Control__w32_char_listen_socket_54e_goodG2BSink(char * data);

/* goodG2B uses the GoodSource with the BadSink */
void CWE114_Process_Control__w32_char_listen_socket_54d_goodG2BSink(char * data)
{
    CWE114_Process_Control__w32_char_listen_socket_54e_goodG2BSink(data);
}

#endif /* OMITGOOD */
