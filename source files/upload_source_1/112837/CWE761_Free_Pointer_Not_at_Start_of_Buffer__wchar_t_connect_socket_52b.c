/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_connect_socket_52b.c
Label Definition File: CWE761_Free_Pointer_Not_at_Start_of_Buffer.label.xml
Template File: source-sinks-52b.tmpl.c
*/
/*
 * @description
 * CWE: 761 Free Pointer not at Start of Buffer
 * BadSource: connect_socket Read data using a connect socket (client side)
 * Sinks:
 *    GoodSink: free() memory correctly at the start of the buffer
 *    BadSink : free() memory not at the start of the buffer
 * Flow Variant: 52 Data flow: data passed as an argument from one function to another to another in three different source files
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

#define SEARCH_CHAR L'S'

#ifndef OMITBAD

/* bad function declaration */
void CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_connect_socket_52c_badSink(wchar_t * data);

void CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_connect_socket_52b_badSink(wchar_t * data)
{
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_connect_socket_52c_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G uses the BadSource with the GoodSink */
void CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_connect_socket_52c_goodB2GSink(wchar_t * data);

void CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_connect_socket_52b_goodB2GSink(wchar_t * data)
{
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_connect_socket_52c_goodB2GSink(data);
}

#endif /* OMITGOOD */
