/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE78_OS_Command_Injection__char_connect_socket_popen_22a.c
Label Definition File: CWE78_OS_Command_Injection.one_string.label.xml
Template File: sources-sink-22a.tmpl.c
*/
/*
 * @description
 * CWE: 78 OS Command Injection
 * BadSource: connect_socket Read data using a connect socket (client side)
 * GoodSource: Fixed string
 * Sink: popen
 *    BadSink : Execute command in data using popen()
 * Flow Variant: 22 Control flow: Flow controlled by value of a global variable. Sink functions are in a separate file from sources.
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

/* define POPEN as _popen on Windows and popen otherwise */
#ifdef _WIN32
#define POPEN _popen
#define PCLOSE _pclose
#else /* NOT _WIN32 */
#define POPEN popen
#define PCLOSE pclose
#endif

#ifndef OMITBAD

/* The global variable below is used to drive control flow in the source function */
int CWE78_OS_Command_Injection__char_connect_socket_popen_22_badGlobal = 0;

char * CWE78_OS_Command_Injection__char_connect_socket_popen_22_badSource(char * data);

void CWE78_OS_Command_Injection__char_connect_socket_popen_22_bad()
{
    char * data;
    char data_buf[100] = FULL_COMMAND;
    data = data_buf;
    CWE78_OS_Command_Injection__char_connect_socket_popen_22_badGlobal = 1; /* true */
    data = CWE78_OS_Command_Injection__char_connect_socket_popen_22_badSource(data);
    {
        FILE *pipe;
        /* POTENTIAL FLAW: Execute command in data possibly leading to command injection */
        pipe = POPEN(data, "wb");
        if (pipe != NULL)
        {
            PCLOSE(pipe);
        }
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* The global variables below are used to drive control flow in the source functions. */
int CWE78_OS_Command_Injection__char_connect_socket_popen_22_goodG2B1Global = 0;
int CWE78_OS_Command_Injection__char_connect_socket_popen_22_goodG2B2Global = 0;

/* goodG2B1() - use goodsource and badsink by setting the static variable to false instead of true */
char * CWE78_OS_Command_Injection__char_connect_socket_popen_22_goodG2B1Source(char * data);

static void goodG2B1()
{
    char * data;
    char data_buf[100] = FULL_COMMAND;
    data = data_buf;
    CWE78_OS_Command_Injection__char_connect_socket_popen_22_goodG2B1Global = 0; /* false */
    data = CWE78_OS_Command_Injection__char_connect_socket_popen_22_goodG2B1Source(data);
    {
        FILE *pipe;
        /* POTENTIAL FLAW: Execute command in data possibly leading to command injection */
        pipe = POPEN(data, "wb");
        if (pipe != NULL)
        {
            PCLOSE(pipe);
        }
    }
}

/* goodG2B2() - use goodsource and badsink by reversing the blocks in the if in the source function */
char * CWE78_OS_Command_Injection__char_connect_socket_popen_22_goodG2B2Source(char * data);

static void goodG2B2()
{
    char * data;
    char data_buf[100] = FULL_COMMAND;
    data = data_buf;
    CWE78_OS_Command_Injection__char_connect_socket_popen_22_goodG2B2Global = 1; /* true */
    data = CWE78_OS_Command_Injection__char_connect_socket_popen_22_goodG2B2Source(data);
    {
        FILE *pipe;
        /* POTENTIAL FLAW: Execute command in data possibly leading to command injection */
        pipe = POPEN(data, "wb");
        if (pipe != NULL)
        {
            PCLOSE(pipe);
        }
    }
}

void CWE78_OS_Command_Injection__char_connect_socket_popen_22_good()
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
    CWE78_OS_Command_Injection__char_connect_socket_popen_22_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE78_OS_Command_Injection__char_connect_socket_popen_22_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
