/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE15_External_Control_of_System_or_Configuration_Setting__w32_82a.cpp
Label Definition File: CWE15_External_Control_of_System_or_Configuration_Setting__w32.label.xml
Template File: sources-sink-82a.tmpl.cpp
*/
/*
 * @description
 * CWE: 15 External Control of System or Configuration Setting
 * BadSource:  Get the hostname from a network socket
 * GoodSource: Get the hostname from a string literal
 * Sinks:
 *    BadSink : Set the hostname
 * Flow Variant: 82 Data flow: data passed in a parameter to an virtual method called via a pointer
 *
 * */

#include "std_testcase.h"
#include "CWE15_External_Control_of_System_or_Configuration_Setting__w32_82.h"

#include <winsock2.h>
#pragma comment(lib, "ws2_32")

#define LISTEN_PORT 999
#define LISTEN_BACKLOG 5

namespace CWE15_External_Control_of_System_or_Configuration_Setting__w32_82
{

#ifndef OMITBAD

void bad()
{
    char * data;
    char dataBuffer[100] = "";
    data = dataBuffer;
    {
        WSADATA wsaData;
        BOOL wsaDataInit = FALSE;
        SOCKET listenSocket = INVALID_SOCKET;
        SOCKET acceptSocket = INVALID_SOCKET;
        struct sockaddr_in service;
        int recvResult;
        do
        {
            if (WSAStartup(MAKEWORD(2,2), &wsaData) != NO_ERROR)
            {
                break;
            }
            wsaDataInit = 1;
            listenSocket = socket(PF_INET, SOCK_STREAM, 0);
            if (listenSocket == INVALID_SOCKET)
            {
                break;
            }
            memset(&service, 0, sizeof(service));
            service.sin_family = AF_INET;
            service.sin_addr.s_addr = INADDR_ANY;
            service.sin_port = htons(LISTEN_PORT);
            if (SOCKET_ERROR == bind(listenSocket, (struct sockaddr*)&service, sizeof(service)))
            {
                break;
            }
            if (SOCKET_ERROR == listen(listenSocket, LISTEN_BACKLOG))
            {
                break;
            }
            acceptSocket = accept(listenSocket, NULL, NULL);
            if (acceptSocket == INVALID_SOCKET)
            {
                break;
            }
            /* INCIDENTAL CWE 188 - reliance on data memory layout
             * recv and friends return "number of bytes" received
             * char's on our system, however, may not be "octets" (8-bit
             * bytes) but could be just about anything.  Also,
             * even if the external environment is ASCII or UTF8,
             * the ANSI/ISO C standard does not dictate that the
             * character set used by the actual language or character
             * constants matches.
             *
             * In practice none of these are usually issues...
             */
            /* FLAW: read the new hostname from a network socket */
            recvResult = recv(acceptSocket, data, 100 - 1, 0);
            if (recvResult == SOCKET_ERROR || recvResult == 0)
            {
                break;
            }
            data[recvResult] = '\0';
        }
        while (0);
        if (acceptSocket != INVALID_SOCKET)
        {
            closesocket(acceptSocket);
        }
        if (listenSocket != INVALID_SOCKET)
        {
            closesocket(listenSocket);
        }
        if (wsaDataInit)
        {
            WSACleanup();
        }
    }
    CWE15_External_Control_of_System_or_Configuration_Setting__w32_82_base* baseObject = new CWE15_External_Control_of_System_or_Configuration_Setting__w32_82_bad;
    baseObject->action(data);
    delete baseObject;
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B()
{
    char * data;
    char dataBuffer[100] = "";
    data = dataBuffer;
    /* FIX: get the hostname from a string literal */
    strcpy(data, "hostname");
    CWE15_External_Control_of_System_or_Configuration_Setting__w32_82_base* baseObject = new CWE15_External_Control_of_System_or_Configuration_Setting__w32_82_goodG2B;
    baseObject->action(data);
    delete baseObject;
}

void good()
{
    goodG2B();
}

#endif /* OMITGOOD */

} /* close namespace */

/* Below is the main(). It is only used when building this testcase on
 * its own for testing or for building a binary to use in testing binary
 * analysis tools. It is not used when compiling all the testcases as one
 * application, which is how source code analysis tools are tested.
 */

#ifdef INCLUDEMAIN

using namespace CWE15_External_Control_of_System_or_Configuration_Setting__w32_82; /* so that we can use good and bad easily */

int main(int argc, char * argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
    printLine("Calling good()...");
    good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
