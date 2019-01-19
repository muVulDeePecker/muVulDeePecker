/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE606_Unchecked_Loop_Condition__wchar_t_listen_socket_53b.c
Label Definition File: CWE606_Unchecked_Loop_Condition.label.xml
Template File: sources-sinks-53b.tmpl.c
*/
/*
 * @description
 * CWE: 606 Unchecked Input For Loop Condition
 * BadSource: listen_socket Read data using a listen socket (server side)
 * GoodSource: Input a number less than MAX_LOOP
 * Sinks:
 *    GoodSink: Use data as the for loop variant after checking to see if it is less than MAX_LOOP
 *    BadSink : Use data as the for loop variant without checking its size
 * Flow Variant: 53 Data flow: data passed as an argument from one function through two others to a fourth; all four functions are in different source files
 *
 * */

#include "std_testcase.h"

#define MAX_LOOP 10000

#ifndef _WIN32
#include <wchar.h>
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

#ifndef OMITBAD

/* bad function declaration */
void CWE606_Unchecked_Loop_Condition__wchar_t_listen_socket_53c_badSink(wchar_t * data);

void CWE606_Unchecked_Loop_Condition__wchar_t_listen_socket_53b_badSink(wchar_t * data)
{
    CWE606_Unchecked_Loop_Condition__wchar_t_listen_socket_53c_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE606_Unchecked_Loop_Condition__wchar_t_listen_socket_53c_goodG2BSink(wchar_t * data);

void CWE606_Unchecked_Loop_Condition__wchar_t_listen_socket_53b_goodG2BSink(wchar_t * data)
{
    CWE606_Unchecked_Loop_Condition__wchar_t_listen_socket_53c_goodG2BSink(data);
}

/* goodB2G uses the BadSource with the GoodSink */
void CWE606_Unchecked_Loop_Condition__wchar_t_listen_socket_53c_goodB2GSink(wchar_t * data);

void CWE606_Unchecked_Loop_Condition__wchar_t_listen_socket_53b_goodB2GSink(wchar_t * data)
{
    CWE606_Unchecked_Loop_Condition__wchar_t_listen_socket_53c_goodB2GSink(data);
}

#endif /* OMITGOOD */
