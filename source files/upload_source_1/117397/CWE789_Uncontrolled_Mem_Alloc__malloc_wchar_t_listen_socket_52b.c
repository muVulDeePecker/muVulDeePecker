/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_listen_socket_52b.c
Label Definition File: CWE789_Uncontrolled_Mem_Alloc__malloc.label.xml
Template File: sources-sinks-52b.tmpl.c
*/
/*
 * @description
 * CWE: 789 Uncontrolled Memory Allocation
 * BadSource: listen_socket Read data using a listen socket (server side)
 * GoodSource: Small number greater than zero
 * Sinks:
 *    GoodSink: Allocate memory with malloc() and check the size of the memory to be allocated
 *    BadSink : Allocate memory with malloc(), but incorrectly check the size of the memory to be allocated
 * Flow Variant: 52 Data flow: data passed as an argument from one function to another to another in three different source files
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
#define CHAR_ARRAY_SIZE (3 * sizeof(data) + 2)

#define HELLO_STRING L"hello"

#ifndef OMITBAD

/* bad function declaration */
void CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_listen_socket_52c_badSink(size_t data);

void CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_listen_socket_52b_badSink(size_t data)
{
    CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_listen_socket_52c_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_listen_socket_52c_goodG2BSink(size_t data);

void CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_listen_socket_52b_goodG2BSink(size_t data)
{
    CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_listen_socket_52c_goodG2BSink(data);
}

/* goodB2G uses the BadSource with the GoodSink */
void CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_listen_socket_52c_goodB2GSink(size_t data);

void CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_listen_socket_52b_goodB2GSink(size_t data)
{
    CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_listen_socket_52c_goodB2GSink(data);
}

#endif /* OMITGOOD */
