/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE789_Uncontrolled_Mem_Alloc__malloc_char_connect_socket_11.c
Label Definition File: CWE789_Uncontrolled_Mem_Alloc__malloc.label.xml
Template File: sources-sinks-11.tmpl.c
*/
/*
 * @description
 * CWE: 789 Uncontrolled Memory Allocation
 * BadSource: connect_socket Read data using a connect socket (client side)
 * GoodSource: Small number greater than zero
 * Sinks:
 *    GoodSink: Allocate memory with malloc() and check the size of the memory to be allocated
 *    BadSink : Allocate memory with malloc(), but incorrectly check the size of the memory to be allocated
 * Flow Variant: 11 Control flow: if(globalReturnsTrue()) and if(globalReturnsFalse())
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

#define HELLO_STRING "hello"

#ifndef OMITBAD

void CWE789_Uncontrolled_Mem_Alloc__malloc_char_connect_socket_11_bad()
{
    size_t data;
    /* Initialize data */
    data = 0;
    if(globalReturnsTrue())
    {
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
                /* Convert to unsigned int */
                data = strtoul(inputBuffer, NULL, 0);
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
    }
    if(globalReturnsTrue())
    {
        {
            char * myString;
            /* POTENTIAL FLAW: No MAXIMUM limitation for memory allocation, but ensure data is large enough
             * for the strcpy() function to not cause a buffer overflow */
            /* INCIDENTAL FLAW: The source could cause a type overrun in data or in the memory allocation */
            if (data > strlen(HELLO_STRING))
            {
                myString = (char *)malloc(data*sizeof(char));
                /* Copy a small string into myString */
                strcpy(myString, HELLO_STRING);
                printLine(myString);
                free(myString);
            }
            else
            {
                printLine("Input is less than the length of the source string");
            }
        }
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G1() - use badsource and goodsink by changing the second globalReturnsTrue() to globalReturnsFalse() */
static void goodB2G1()
{
    size_t data;
    /* Initialize data */
    data = 0;
    if(globalReturnsTrue())
    {
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
                /* Convert to unsigned int */
                data = strtoul(inputBuffer, NULL, 0);
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
    }
    if(globalReturnsFalse())
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        {
            char * myString;
            /* FIX: Include a MAXIMUM limitation for memory allocation and a check to ensure data is large enough
             * for the strcpy() function to not cause a buffer overflow */
            /* INCIDENTAL FLAW: The source could cause a type overrun in data or in the memory allocation */
            if (data > strlen(HELLO_STRING) && data < 100)
            {
                myString = (char *)malloc(data*sizeof(char));
                /* Copy a small string into myString */
                strcpy(myString, HELLO_STRING);
                printLine(myString);
                free(myString);
            }
            else
            {
                printLine("Input is less than the length of the source string or too large");
            }
        }
    }
}

/* goodB2G2() - use badsource and goodsink by reversing the blocks in the second if */
static void goodB2G2()
{
    size_t data;
    /* Initialize data */
    data = 0;
    if(globalReturnsTrue())
    {
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
                /* Convert to unsigned int */
                data = strtoul(inputBuffer, NULL, 0);
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
    }
    if(globalReturnsTrue())
    {
        {
            char * myString;
            /* FIX: Include a MAXIMUM limitation for memory allocation and a check to ensure data is large enough
             * for the strcpy() function to not cause a buffer overflow */
            /* INCIDENTAL FLAW: The source could cause a type overrun in data or in the memory allocation */
            if (data > strlen(HELLO_STRING) && data < 100)
            {
                myString = (char *)malloc(data*sizeof(char));
                /* Copy a small string into myString */
                strcpy(myString, HELLO_STRING);
                printLine(myString);
                free(myString);
            }
            else
            {
                printLine("Input is less than the length of the source string or too large");
            }
        }
    }
}

/* goodG2B1() - use goodsource and badsink by changing the first globalReturnsTrue() to globalReturnsFalse() */
static void goodG2B1()
{
    size_t data;
    /* Initialize data */
    data = 0;
    if(globalReturnsFalse())
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        /* FIX: Use a relatively small number for memory allocation */
        data = 20;
    }
    if(globalReturnsTrue())
    {
        {
            char * myString;
            /* POTENTIAL FLAW: No MAXIMUM limitation for memory allocation, but ensure data is large enough
             * for the strcpy() function to not cause a buffer overflow */
            /* INCIDENTAL FLAW: The source could cause a type overrun in data or in the memory allocation */
            if (data > strlen(HELLO_STRING))
            {
                myString = (char *)malloc(data*sizeof(char));
                /* Copy a small string into myString */
                strcpy(myString, HELLO_STRING);
                printLine(myString);
                free(myString);
            }
            else
            {
                printLine("Input is less than the length of the source string");
            }
        }
    }
}

/* goodG2B2() - use goodsource and badsink by reversing the blocks in the first if */
static void goodG2B2()
{
    size_t data;
    /* Initialize data */
    data = 0;
    if(globalReturnsTrue())
    {
        /* FIX: Use a relatively small number for memory allocation */
        data = 20;
    }
    if(globalReturnsTrue())
    {
        {
            char * myString;
            /* POTENTIAL FLAW: No MAXIMUM limitation for memory allocation, but ensure data is large enough
             * for the strcpy() function to not cause a buffer overflow */
            /* INCIDENTAL FLAW: The source could cause a type overrun in data or in the memory allocation */
            if (data > strlen(HELLO_STRING))
            {
                myString = (char *)malloc(data*sizeof(char));
                /* Copy a small string into myString */
                strcpy(myString, HELLO_STRING);
                printLine(myString);
                free(myString);
            }
            else
            {
                printLine("Input is less than the length of the source string");
            }
        }
    }
}

void CWE789_Uncontrolled_Mem_Alloc__malloc_char_connect_socket_11_good()
{
    goodB2G1();
    goodB2G2();
    goodG2B1();
    goodG2B2();
}

#endif /* OMITGOOD */

/* Below is the main(). It is only used when building this testcase on
   its own for testing or for building a binary to use in testing binary
   analysis tools. It is not used when compiling all the testcases as one
   application, which is how source code analysis tools are tested. */

#ifdef INCLUDEMAIN

int main(int argc, char * argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
    printLine("Calling good()...");
    CWE789_Uncontrolled_Mem_Alloc__malloc_char_connect_socket_11_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE789_Uncontrolled_Mem_Alloc__malloc_char_connect_socket_11_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
