/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE190_Integer_Overflow__int_connect_socket_square_54c.c
Label Definition File: CWE190_Integer_Overflow__int.label.xml
Template File: sources-sinks-54c.tmpl.c
*/
/*
 * @description
 * CWE: 190 Integer Overflow
 * BadSource: connect_socket Read data using a connect socket (client side)
 * GoodSource: Set data to a small, non-zero number (two)
 * Sinks: square
 *    GoodSink: Ensure there will not be an overflow before squaring data
 *    BadSink : Square data, which can lead to overflow
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

#include <math.h>

#ifndef OMITBAD

/* bad function declaration */
void CWE190_Integer_Overflow__int_connect_socket_square_54d_badSink(int data);

void CWE190_Integer_Overflow__int_connect_socket_square_54c_badSink(int data)
{
    CWE190_Integer_Overflow__int_connect_socket_square_54d_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE190_Integer_Overflow__int_connect_socket_square_54d_goodG2BSink(int data);

void CWE190_Integer_Overflow__int_connect_socket_square_54c_goodG2BSink(int data)
{
    CWE190_Integer_Overflow__int_connect_socket_square_54d_goodG2BSink(data);
}

/* goodB2G uses the BadSource with the GoodSink */
void CWE190_Integer_Overflow__int_connect_socket_square_54d_goodB2GSink(int data);

void CWE190_Integer_Overflow__int_connect_socket_square_54c_goodB2GSink(int data)
{
    CWE190_Integer_Overflow__int_connect_socket_square_54d_goodB2GSink(data);
}

#endif /* OMITGOOD */
