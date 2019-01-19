/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE123_Write_What_Where_Condition__connect_socket_54b.c
Label Definition File: CWE123_Write_What_Where_Condition.label.xml
Template File: sources-sink-54b.tmpl.c
*/
/*
 * @description
 * CWE: 123 Write-What-Where Condition
 * BadSource: connect_socket Overwrite linked list pointers using a connect socket (client side)
 * GoodSource: Don't overwrite linked list pointers
 * Sink:
 *    BadSink : Remove element from list
 * Flow Variant: 54 Data flow: data passed as an argument from one function through three others to a fifth; all five functions are in different source files
 *
 * */

#include "std_testcase.h"

typedef struct _linkedList
{
    struct _linkedList *next;
    struct _linkedList *prev;
} linkedList;

typedef struct _badStruct
{
    linkedList list;
} badStruct;

static linkedList *linkedListPrev, *linkedListNext;

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

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

#ifndef OMITBAD

/* bad function declaration */
void CWE123_Write_What_Where_Condition__connect_socket_54c_badSink(badStruct data);

void CWE123_Write_What_Where_Condition__connect_socket_54b_badSink(badStruct data)
{
    CWE123_Write_What_Where_Condition__connect_socket_54c_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good function declaration */
void CWE123_Write_What_Where_Condition__connect_socket_54c_goodG2BSink(badStruct data);

/* goodG2B uses the GoodSource with the BadSink */
void CWE123_Write_What_Where_Condition__connect_socket_54b_goodG2BSink(badStruct data)
{
    CWE123_Write_What_Where_Condition__connect_socket_54c_goodG2BSink(data);
}

#endif /* OMITGOOD */
