/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE78_OS_Command_Injection__wchar_t_listen_socket_w32spawnl_22a.c
Label Definition File: CWE78_OS_Command_Injection.strings.label.xml
Template File: sources-sink-22a.tmpl.c
*/
/*
 * @description
 * CWE: 78 OS Command Injection
 * BadSource: listen_socket Read data using a listen socket (server side)
 * GoodSource: Fixed string
 * Sink: w32spawnl
 *    BadSink : execute command with wspawnl
 * Flow Variant: 22 Control flow: Flow controlled by value of a global variable. Sink functions are in a separate file from sources.
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifdef _WIN32
#define COMMAND_INT_PATH L"%WINDIR%\\system32\\cmd.exe"
#define COMMAND_INT L"cmd.exe"
#define COMMAND_ARG1 L"/c"
#define COMMAND_ARG2 L"dir"
#define COMMAND_ARG3 data
#else /* NOT _WIN32 */
#include <unistd.h>
#define COMMAND_INT_PATH L"/bin/sh"
#define COMMAND_INT L"sh"
#define COMMAND_ARG1 L"ls"
#define COMMAND_ARG2 L"-la"
#define COMMAND_ARG3 data
#endif

#include <process.h>

#ifndef OMITBAD

/* The global variable below is used to drive control flow in the source function */
int CWE78_OS_Command_Injection__wchar_t_listen_socket_w32spawnl_22_badGlobal = 0;

wchar_t * CWE78_OS_Command_Injection__wchar_t_listen_socket_w32spawnl_22_badSource(wchar_t * data);

void CWE78_OS_Command_Injection__wchar_t_listen_socket_w32spawnl_22_bad()
{
    wchar_t * data;
    wchar_t dataBuffer[100] = L"";
    data = dataBuffer;
    CWE78_OS_Command_Injection__wchar_t_listen_socket_w32spawnl_22_badGlobal = 1; /* true */
    data = CWE78_OS_Command_Injection__wchar_t_listen_socket_w32spawnl_22_badSource(data);
    /* wspawnl - specify the path where the command is located */
    /* POTENTIAL FLAW: Execute command without validating input possibly leading to command injection */
    _wspawnl(_P_WAIT, COMMAND_INT_PATH, COMMAND_INT_PATH, COMMAND_ARG1, COMMAND_ARG2, COMMAND_ARG3, NULL);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* The global variables below are used to drive control flow in the source functions. */
int CWE78_OS_Command_Injection__wchar_t_listen_socket_w32spawnl_22_goodG2B1Global = 0;
int CWE78_OS_Command_Injection__wchar_t_listen_socket_w32spawnl_22_goodG2B2Global = 0;

/* goodG2B1() - use goodsource and badsink by setting the static variable to false instead of true */
wchar_t * CWE78_OS_Command_Injection__wchar_t_listen_socket_w32spawnl_22_goodG2B1Source(wchar_t * data);

static void goodG2B1()
{
    wchar_t * data;
    wchar_t dataBuffer[100] = L"";
    data = dataBuffer;
    CWE78_OS_Command_Injection__wchar_t_listen_socket_w32spawnl_22_goodG2B1Global = 0; /* false */
    data = CWE78_OS_Command_Injection__wchar_t_listen_socket_w32spawnl_22_goodG2B1Source(data);
    /* wspawnl - specify the path where the command is located */
    /* POTENTIAL FLAW: Execute command without validating input possibly leading to command injection */
    _wspawnl(_P_WAIT, COMMAND_INT_PATH, COMMAND_INT_PATH, COMMAND_ARG1, COMMAND_ARG2, COMMAND_ARG3, NULL);
}

/* goodG2B2() - use goodsource and badsink by reversing the blocks in the if in the source function */
wchar_t * CWE78_OS_Command_Injection__wchar_t_listen_socket_w32spawnl_22_goodG2B2Source(wchar_t * data);

static void goodG2B2()
{
    wchar_t * data;
    wchar_t dataBuffer[100] = L"";
    data = dataBuffer;
    CWE78_OS_Command_Injection__wchar_t_listen_socket_w32spawnl_22_goodG2B2Global = 1; /* true */
    data = CWE78_OS_Command_Injection__wchar_t_listen_socket_w32spawnl_22_goodG2B2Source(data);
    /* wspawnl - specify the path where the command is located */
    /* POTENTIAL FLAW: Execute command without validating input possibly leading to command injection */
    _wspawnl(_P_WAIT, COMMAND_INT_PATH, COMMAND_INT_PATH, COMMAND_ARG1, COMMAND_ARG2, COMMAND_ARG3, NULL);
}

void CWE78_OS_Command_Injection__wchar_t_listen_socket_w32spawnl_22_good()
{
    goodG2B1();
    goodG2B2();
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
    CWE78_OS_Command_Injection__wchar_t_listen_socket_w32spawnl_22_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE78_OS_Command_Injection__wchar_t_listen_socket_w32spawnl_22_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
