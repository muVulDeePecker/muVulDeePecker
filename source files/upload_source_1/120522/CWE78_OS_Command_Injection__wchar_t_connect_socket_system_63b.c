/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE78_OS_Command_Injection__wchar_t_connect_socket_system_63b.c
Label Definition File: CWE78_OS_Command_Injection.one_string.label.xml
Template File: sources-sink-63b.tmpl.c
*/
/*
 * @description
 * CWE: 78 OS Command Injection
 * BadSource: connect_socket Read data using a connect socket (client side)
 * GoodSource: Fixed string
 * Sinks: system
 *    BadSink : Execute command in data using system()
 * Flow Variant: 63 Data flow: pointer to data passed from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifdef _WIN32
#define FULL_COMMAND L"%WINDIR%\\system32\\cmd.exe /c dir "
#else
#include <unistd.h>
#define FULL_COMMAND L"/bin/sh ls -la "
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
#define SYSTEM _wsystem
#else /* NOT _WIN32 */
#define SYSTEM system
#endif

#ifndef OMITBAD

void CWE78_OS_Command_Injection__wchar_t_connect_socket_system_63b_badSink(wchar_t * * dataPtr)
{
    wchar_t * data = *dataPtr;
    /* POTENTIAL FLAW: Execute command in data possibly leading to command injection */
    if (SYSTEM(data) <= 0)
    {
        printLine("command execution failed!");
        exit(1);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE78_OS_Command_Injection__wchar_t_connect_socket_system_63b_goodG2BSink(wchar_t * * dataPtr)
{
    wchar_t * data = *dataPtr;
    /* POTENTIAL FLAW: Execute command in data possibly leading to command injection */
    if (SYSTEM(data) <= 0)
    {
        printLine("command execution failed!");
        exit(1);
    }
}

#endif /* OMITGOOD */
