/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE134_Uncontrolled_Format_String__char_listen_socket_fprintf_68b.c
Label Definition File: CWE134_Uncontrolled_Format_String.label.xml
Template File: sources-sinks-68b.tmpl.c
*/
/*
 * @description
 * CWE: 134 Uncontrolled Format String
 * BadSource: listen_socket Read data using a listen socket (server side)
 * GoodSource: Copy a fixed string into data
 * Sinks: fprintf
 *    GoodSink: fprintf with "%s" as the second argument and data as the third
 *    BadSink : fprintf with data as the second argument
 * Flow Variant: 68 Data flow: data passed as a global variable from one function to another in different source files
 *
 * */

#include "std_testcase.h"

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

extern char * CWE134_Uncontrolled_Format_String__char_listen_socket_fprintf_68_badData;
extern char * CWE134_Uncontrolled_Format_String__char_listen_socket_fprintf_68_goodG2BData;
extern char * CWE134_Uncontrolled_Format_String__char_listen_socket_fprintf_68_goodB2GData;

#ifndef OMITBAD

void CWE134_Uncontrolled_Format_String__char_listen_socket_fprintf_68b_badSink()
{
    char * data = CWE134_Uncontrolled_Format_String__char_listen_socket_fprintf_68_badData;
    /* POTENTIAL FLAW: Do not specify the format allowing a possible format string vulnerability */
    fprintf(stdout, data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE134_Uncontrolled_Format_String__char_listen_socket_fprintf_68b_goodG2BSink()
{
    char * data = CWE134_Uncontrolled_Format_String__char_listen_socket_fprintf_68_goodG2BData;
    /* POTENTIAL FLAW: Do not specify the format allowing a possible format string vulnerability */
    fprintf(stdout, data);
}

/* goodB2G uses the BadSource with the GoodSink */
void CWE134_Uncontrolled_Format_String__char_listen_socket_fprintf_68b_goodB2GSink()
{
    char * data = CWE134_Uncontrolled_Format_String__char_listen_socket_fprintf_68_goodB2GData;
    /* FIX: Specify the format disallowing a format string vulnerability */
    fprintf(stdout, "%s\n", data);
}

#endif /* OMITGOOD */
