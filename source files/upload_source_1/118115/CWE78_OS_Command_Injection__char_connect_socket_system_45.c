/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE78_OS_Command_Injection__char_connect_socket_system_45.c
Label Definition File: CWE78_OS_Command_Injection.one_string.label.xml
Template File: sources-sink-45.tmpl.c
*/
/*
 * @description
 * CWE: 78 OS Command Injection
 * BadSource: connect_socket Read data using a connect socket (client side)
 * GoodSource: Fixed string
 * Sinks: system
 *    BadSink : Execute command in data using system()
 * Flow Variant: 45 Data flow: data passed as a static global variable from one function to another in the same source file
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifdef _WIN32
#define FULL_COMMAND "%WINDIR%\\system32\\cmd.exe /c dir "
#else
#include <unistd.h>
#define FULL_COMMAND "/bin/sh ls -la "
#endif

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
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define CLOSE_SOCKET close
#define SOCKET int
#endif

#define TCP_PORT 27015
#define IP_ADDRESS "127.0.0.1"

#ifdef _WIN32
#define SYSTEM system
#else /* NOT _WIN32 */
#define SYSTEM system
#endif

static char * CWE78_OS_Command_Injection__char_connect_socket_system_45_badData;
static char * CWE78_OS_Command_Injection__char_connect_socket_system_45_goodG2BData;

#ifndef OMITBAD

static void badSink()
{
    char * data = CWE78_OS_Command_Injection__char_connect_socket_system_45_badData;
    /* POTENTIAL FLAW: Execute command in data possibly leading to command injection */
    if (SYSTEM(data) <= 0)
    {
        printLine("command execution failed!");
        exit(1);
    }
}

void CWE78_OS_Command_Injection__char_connect_socket_system_45_bad()
{
    char * data;
    char data_buf[100] = FULL_COMMAND;
    data = data_buf;
    {
#ifdef _WIN32
        WSADATA wsaData;
        int wsaDataInit = 0;
#endif
        int recvResult;
        struct sockaddr_in service;
        char *replace;
        SOCKET connectSocket = INVALID_SOCKET;
        size_t dataLen = strlen(data);
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
            /* Abort on error or the connection was closed */
            recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0);
            if (recvResult == SOCKET_ERROR || recvResult == 0)
            {
                break;
            }
            /* Append null terminator */
            data[dataLen + recvResult / sizeof(char)] = '\0';
            /* Eliminate CRLF */
            replace = strchr(data, '\r');
            if (replace)
            {
                *replace = '\0';
            }
            replace = strchr(data, '\n');
            if (replace)
            {
                *replace = '\0';
            }
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
    CWE78_OS_Command_Injection__char_connect_socket_system_45_badData = data;
    badSink();
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B() uses the GoodSource with the BadSink */
static void goodG2BSink()
{
    char * data = CWE78_OS_Command_Injection__char_connect_socket_system_45_goodG2BData;
    /* POTENTIAL FLAW: Execute command in data possibly leading to command injection */
    if (SYSTEM(data) <= 0)
    {
        printLine("command execution failed!");
        exit(1);
    }
}

static void goodG2B()
{
    char * data;
    char data_buf[100] = FULL_COMMAND;
    data = data_buf;
    /* FIX: Append a fixed string to data (not user / external input) */
    strcat(data, "*.*");
    CWE78_OS_Command_Injection__char_connect_socket_system_45_goodG2BData = data;
    goodG2BSink();
}

void CWE78_OS_Command_Injection__char_connect_socket_system_45_good()
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
    CWE78_OS_Command_Injection__char_connect_socket_system_45_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE78_OS_Command_Injection__char_connect_socket_system_45_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
