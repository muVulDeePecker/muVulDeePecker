/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE195_Signed_to_Unsigned_Conversion_Error__connect_socket_memcpy_67a.c
Label Definition File: CWE195_Signed_to_Unsigned_Conversion_Error.label.xml
Template File: sources-sink-67a.tmpl.c
*/
/*
 * @description
 * CWE: 195 Signed to Unsigned Conversion Error
 * BadSource: connect_socket Read data using a connect socket (client side)
 * GoodSource: Positive integer
 * Sinks: memcpy
 *    BadSink : Copy strings using memcpy() with the length of data
 * Flow Variant: 67 Data flow: data passed in a struct from one function to another in different source files
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

typedef struct _CWE195_Signed_to_Unsigned_Conversion_Error__connect_socket_memcpy_67_structType
{
    int structFirst;
} CWE195_Signed_to_Unsigned_Conversion_Error__connect_socket_memcpy_67_structType;

#ifndef OMITBAD

/* bad function declaration */
void CWE195_Signed_to_Unsigned_Conversion_Error__connect_socket_memcpy_67b_badSink(CWE195_Signed_to_Unsigned_Conversion_Error__connect_socket_memcpy_67_structType myStruct);

void CWE195_Signed_to_Unsigned_Conversion_Error__connect_socket_memcpy_67_bad()
{
    int data;
    CWE195_Signed_to_Unsigned_Conversion_Error__connect_socket_memcpy_67_structType myStruct;
    /* Initialize data */
    data = -1;
    {
#ifdef _WIN32
        WSADATA wsaData;
        int wsaDataInit = 0;
#endif
        int recvResult;
        struct sockaddr_in service;
        SOCKET connectSocket = INVALID_SOCKET;
        char inputBuffer[CHAR_ARRAY_SIZE];
        do
        {
#ifdef _WIN32
            if (WSAStartup(MAKEWORD(2,2), &wsaData) != NO_ERROR)
            {
                break;
            }
            wsaDataInit = 1;
#endif
            /* POTENTIAL FLAW: Read data using a connect socket */
            connectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (connectSocket == INVALID_SOCKET)
            {
                break;
            }
            memset(&service, 0, sizeof(service));
            service.sin_family = AF_INET;
            service.sin_addr.s_addr = inet_addr(IP_ADDRESS);
            service.sin_port = htons(TCP_PORT);
            if (connect(connectSocket, (struct sockaddr*)&service, sizeof(service)) == SOCKET_ERROR)
            {
                break;
            }
            /* Abort on error or the connection was closed, make sure to recv one
             * less char than is in the recv_buf in order to append a terminator */
            recvResult = recv(connectSocket, inputBuffer, CHAR_ARRAY_SIZE - 1, 0);
            if (recvResult == SOCKET_ERROR || recvResult == 0)
            {
                break;
            }
            /* NUL-terminate the string */
            inputBuffer[recvResult] = '\0';
            /* Convert to int */
            data = atoi(inputBuffer);
        }
        while (0);
        if (connectSocket != INVALID_SOCKET)
        {
            CLOSE_SOCKET(connectSocket);
        }
#ifdef _WIN32
        if (wsaDataInit)
        {
            WSACleanup();
        }
#endif
    }
    myStruct.structFirst = data;
    CWE195_Signed_to_Unsigned_Conversion_Error__connect_socket_memcpy_67b_badSink(myStruct);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE195_Signed_to_Unsigned_Conversion_Error__connect_socket_memcpy_67b_goodG2BSink(CWE195_Signed_to_Unsigned_Conversion_Error__connect_socket_memcpy_67_structType myStruct);

static void goodG2B()
{
    int data;
    CWE195_Signed_to_Unsigned_Conversion_Error__connect_socket_memcpy_67_structType myStruct;
    /* Initialize data */
    data = -1;
    /* FIX: Use a positive integer less than &InitialDataSize&*/
    data = 100-1;
    myStruct.structFirst = data;
    CWE195_Signed_to_Unsigned_Conversion_Error__connect_socket_memcpy_67b_goodG2BSink(myStruct);
}

void CWE195_Signed_to_Unsigned_Conversion_Error__connect_socket_memcpy_67_good()
{
    goodG2B();
}

#endif /* OMITGOOD */

/* Below is the main(). It is only used when building this testcase on
 * its own for testing or for building a binary to use in testing binary
 * analysis tools. It is not used when compiling all the testcases as one
 * application, which is how source code analysis tools are tested.
 */

#ifdef INCLUDEMAIN

int main(int argc, char * argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
    printLine("Calling good()...");
    CWE195_Signed_to_Unsigned_Conversion_Error__connect_socket_memcpy_67_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE195_Signed_to_Unsigned_Conversion_Error__connect_socket_memcpy_67_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
