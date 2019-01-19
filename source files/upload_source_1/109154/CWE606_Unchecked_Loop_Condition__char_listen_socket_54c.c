/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE606_Unchecked_Loop_Condition__char_listen_socket_54c.c
Label Definition File: CWE606_Unchecked_Loop_Condition.label.xml
Template File: sources-sinks-54c.tmpl.c
*/
/*
 * @description
 * CWE: 606 Unchecked Input For Loop Condition
 * BadSource: listen_socket Read data using a listen socket (server side)
 * GoodSource: Input a number less than MAX_LOOP
 * Sinks:
 *    GoodSink: Use data as the for loop variant after checking to see if it is less than MAX_LOOP
 *    BadSink : Use data as the for loop variant without checking its size
 * Flow Variant: 54 Data flow: data passed as an argument from one function through three others to a fifth; all five functions are in different source files
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
void CWE606_Unchecked_Loop_Condition__char_listen_socket_54d_badSink(char * data);

void CWE606_Unchecked_Loop_Condition__char_listen_socket_54c_badSink(char * data)
{
    CWE606_Unchecked_Loop_Condition__char_listen_socket_54d_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE606_Unchecked_Loop_Condition__char_listen_socket_54d_goodG2BSink(char * data);

void CWE606_Unchecked_Loop_Condition__char_listen_socket_54c_goodG2BSink(char * data)
{
    CWE606_Unchecked_Loop_Condition__char_listen_socket_54d_goodG2BSink(data);
}

/* goodB2G uses the BadSource with the GoodSink */
void CWE606_Unchecked_Loop_Condition__char_listen_socket_54d_goodB2GSink(char * data);

void CWE606_Unchecked_Loop_Condition__char_listen_socket_54c_goodB2GSink(char * data)
{
    CWE606_Unchecked_Loop_Condition__char_listen_socket_54d_goodB2GSink(data);
}

#endif /* OMITGOOD */
