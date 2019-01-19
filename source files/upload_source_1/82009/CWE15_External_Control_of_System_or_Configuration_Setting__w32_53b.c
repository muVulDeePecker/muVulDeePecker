/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE15_External_Control_of_System_or_Configuration_Setting__w32_53b.c
Label Definition File: CWE15_External_Control_of_System_or_Configuration_Setting__w32.label.xml
Template File: sources-sink-53b.tmpl.c
*/
/*
 * @description
 * CWE: 15 External Control of System or Configuration Setting
 * BadSource:  Get the hostname from a network socket
 * GoodSource: Get the hostname from a string literal
 * Sink:
 *    BadSink : Set the hostname
 * Flow Variant: 53 Data flow: data passed as an argument from one function through two others to a fourth; all four functions are in different source files
 *
 * */

#include "std_testcase.h"

#include <winsock2.h>
#pragma comment(lib, "ws2_32")

#define LISTEN_PORT 999
#define LISTEN_BACKLOG 5

#include <windows.h>

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

#ifndef OMITBAD

/* bad function declaration */
void CWE15_External_Control_of_System_or_Configuration_Setting__w32_53c_badSink(char * data);

void CWE15_External_Control_of_System_or_Configuration_Setting__w32_53b_badSink(char * data)
{
    CWE15_External_Control_of_System_or_Configuration_Setting__w32_53c_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good function declaration */
void CWE15_External_Control_of_System_or_Configuration_Setting__w32_53c_goodG2BSink(char * data);

/* goodG2B uses the GoodSource with the BadSink */
void CWE15_External_Control_of_System_or_Configuration_Setting__w32_53b_goodG2BSink(char * data)
{
    CWE15_External_Control_of_System_or_Configuration_Setting__w32_53c_goodG2BSink(data);
}

#endif /* OMITGOOD */
