/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE400_Resource_Exhaustion__listen_socket_fwrite_53c.c
Label Definition File: CWE400_Resource_Exhaustion.label.xml
Template File: sources-sinks-53c.tmpl.c
*/
/*
 * @description
 * CWE: 400 Resource Exhaustion
 * BadSource: listen_socket Read data using a listen socket (server side)
 * GoodSource: Assign count to be a relatively small number
 * Sinks: fwrite
 *    GoodSink: Write to a file count number of times, but first validate count
 *    BadSink : Write to a file count number of times
 * Flow Variant: 53 Data flow: data passed as an argument from one function through two others to a fourth; all four functions are in different source files
 *
 * */

#include "std_testcase.h"

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
#define CHAR_ARRAY_SIZE (3 * sizeof(count) + 2)

#define SENTENCE "This is the sentence we are printing to the file. "

#ifndef OMITBAD

/* bad function declaration */
void CWE400_Resource_Exhaustion__listen_socket_fwrite_53d_badSink(int count);

void CWE400_Resource_Exhaustion__listen_socket_fwrite_53c_badSink(int count)
{
    CWE400_Resource_Exhaustion__listen_socket_fwrite_53d_badSink(count);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE400_Resource_Exhaustion__listen_socket_fwrite_53d_goodG2BSink(int count);

void CWE400_Resource_Exhaustion__listen_socket_fwrite_53c_goodG2BSink(int count)
{
    CWE400_Resource_Exhaustion__listen_socket_fwrite_53d_goodG2BSink(count);
}

/* goodB2G uses the BadSource with the GoodSink */
void CWE400_Resource_Exhaustion__listen_socket_fwrite_53d_goodB2GSink(int count);

void CWE400_Resource_Exhaustion__listen_socket_fwrite_53c_goodB2GSink(int count)
{
    CWE400_Resource_Exhaustion__listen_socket_fwrite_53d_goodB2GSink(count);
}

#endif /* OMITGOOD */
