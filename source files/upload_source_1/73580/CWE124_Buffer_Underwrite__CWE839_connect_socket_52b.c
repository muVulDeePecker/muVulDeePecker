/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE124_Buffer_Underwrite__CWE839_connect_socket_52b.c
Label Definition File: CWE124_Buffer_Underwrite__CWE839.label.xml
Template File: sources-sinks-52b.tmpl.c
*/
/*
 * @description
 * CWE: 124 Buffer Underwrite
 * BadSource: connect_socket Read data using a connect socket (client side)
 * GoodSource: Non-negative but less than 10
 * Sinks:
 *    GoodSink: Ensure the array index is valid
 *    BadSink : Improperly check the array index by not checking the lower bound
 * Flow Variant: 52 Data flow: data passed as an argument from one function to another to another in three different source files
 *
 * */

#include "std_testcase.h"

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
#define CHAR_ARRAY_SIZE (3 * sizeof(data) + 2)

#ifndef OMITBAD

/* bad function declaration */
void CWE124_Buffer_Underwrite__CWE839_connect_socket_52c_badSink(int data);

void CWE124_Buffer_Underwrite__CWE839_connect_socket_52b_badSink(int data)
{
    CWE124_Buffer_Underwrite__CWE839_connect_socket_52c_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE124_Buffer_Underwrite__CWE839_connect_socket_52c_goodG2BSink(int data);

void CWE124_Buffer_Underwrite__CWE839_connect_socket_52b_goodG2BSink(int data)
{
    CWE124_Buffer_Underwrite__CWE839_connect_socket_52c_goodG2BSink(data);
}

/* goodB2G uses the BadSource with the GoodSink */
void CWE124_Buffer_Underwrite__CWE839_connect_socket_52c_goodB2GSink(int data);

void CWE124_Buffer_Underwrite__CWE839_connect_socket_52b_goodB2GSink(int data)
{
    CWE124_Buffer_Underwrite__CWE839_connect_socket_52c_goodB2GSink(data);
}

#endif /* OMITGOOD */
