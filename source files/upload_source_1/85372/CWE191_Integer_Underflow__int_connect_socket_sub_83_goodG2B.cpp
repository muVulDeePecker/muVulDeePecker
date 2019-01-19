/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE191_Integer_Underflow__int_connect_socket_sub_83_goodG2B.cpp
Label Definition File: CWE191_Integer_Underflow__int.label.xml
Template File: sources-sinks-83_goodG2B.tmpl.cpp
*/
/*
 * @description
 * CWE: 191 Integer Underflow
 * BadSource: connect_socket Read data using a connect socket (client side)
 * GoodSource: Set data to a small, non-zero number (negative two)
 * Sinks: sub
 *    GoodSink: Ensure there will not be an underflow before subtracting 1 from data
 *    BadSink : Subtract 1 from data, which can cause an Underflow
 * Flow Variant: 83 Data flow: data passed to class constructor and destructor by declaring the class object on the stack
 *
 * */
#ifndef OMITGOOD

#include "std_testcase.h"
#include "CWE191_Integer_Underflow__int_connect_socket_sub_83.h"

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

namespace CWE191_Integer_Underflow__int_connect_socket_sub_83
{
CWE191_Integer_Underflow__int_connect_socket_sub_83_goodG2B::CWE191_Integer_Underflow__int_connect_socket_sub_83_goodG2B(int dataCopy)
{
    data = dataCopy;
    /* FIX: Use a small, non-zero value that will not cause an integer underflow in the sinks */
    data = -2;
}

CWE191_Integer_Underflow__int_connect_socket_sub_83_goodG2B::~CWE191_Integer_Underflow__int_connect_socket_sub_83_goodG2B()
{
    {
        /* POTENTIAL FLAW: Subtracting 1 from data could cause an underflow */
        int result = data - 1;
        printIntLine(result);
    }
}
}
#endif /* OMITGOOD */
