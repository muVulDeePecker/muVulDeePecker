/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE15_External_Control_of_System_or_Configuration_Setting__w32_65b.c
Label Definition File: CWE15_External_Control_of_System_or_Configuration_Setting__w32.label.xml
Template File: sources-sink-65b.tmpl.c
*/
/*
 * @description
 * CWE: 15 External Control of System or Configuration Setting
 * BadSource:  Get the hostname from a network socket
 * GoodSource: Get the hostname from a string literal
 * Sinks:
 *    BadSink : Set the hostname
 * Flow Variant: 65 Data/control flow: data passed as an argument from one function to a function in a different source file called via a function pointer
 *
 * */

#include "std_testcase.h"

#include <winsock2.h>
#pragma comment(lib, "ws2_32")

#define LISTEN_PORT 999
#define LISTEN_BACKLOG 5

#include <windows.h>

#ifndef OMITBAD

void CWE15_External_Control_of_System_or_Configuration_Setting__w32_65b_badSink(char * data)
{
    /* POTENTIAL FLAW: set the hostname to data obtained from a potentially external source */
    if (!SetComputerNameA(data))
    {
        printLine("Failure setting computer name");
        exit(1);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE15_External_Control_of_System_or_Configuration_Setting__w32_65b_goodG2BSink(char * data)
{
    /* POTENTIAL FLAW: set the hostname to data obtained from a potentially external source */
    if (!SetComputerNameA(data))
    {
        printLine("Failure setting computer name");
        exit(1);
    }
}

#endif /* OMITGOOD */
