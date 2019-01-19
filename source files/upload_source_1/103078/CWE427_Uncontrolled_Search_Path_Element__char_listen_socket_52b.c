/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_52b.c
Label Definition File: CWE427_Uncontrolled_Search_Path_Element.label.xml
Template File: sources-sink-52b.tmpl.c
*/
/*
 * @description
 * CWE: 427 Uncontrolled Search Path Element
 * BadSource: listen_socket Read data using a listen socket (server side)
 * GoodSource: Use a hardcoded path
 * Sink:
 *    BadSink : Set the environment variable
 * Flow Variant: 52 Data flow: data passed as an argument from one function to another to another in three different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>
#ifdef _WIN32
#define NEW_PATH "%SystemRoot%\\system32"
#define PUTENV _putenv
#else
#define NEW_PATH "/bin"
#define PUTENV putenv
#endif

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
void CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_52c_badSink(char * data);

void CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_52b_badSink(char * data)
{
    CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_52c_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good function declaration */
void CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_52c_goodG2BSink(char * data);

/* goodG2B uses the GoodSource with the BadSink */
void CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_52b_goodG2BSink(char * data)
{
    CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_52c_goodG2BSink(data);
}

#endif /* OMITGOOD */
