/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE15_External_Control_of_System_or_Configuration_Setting__w32_22a.c
Label Definition File: CWE15_External_Control_of_System_or_Configuration_Setting__w32.label.xml
Template File: sources-sink-22a.tmpl.c
*/
/*
 * @description
 * CWE: 15 External Control of System or Configuration Setting
 * BadSource:  Get the hostname from a network socket
 * GoodSource: Get the hostname from a string literal
 * Sink:
 *    BadSink : Set the hostname
 * Flow Variant: 22 Control flow: Flow controlled by value of a global variable. Sink functions are in a separate file from sources.
 *
 * */

#include "std_testcase.h"

#include <windows.h>

#ifndef OMITBAD

/* The global variable below is used to drive control flow in the source function */
int CWE15_External_Control_of_System_or_Configuration_Setting__w32_22_badGlobal = 0;

char * CWE15_External_Control_of_System_or_Configuration_Setting__w32_22_badSource(char * data);

void CWE15_External_Control_of_System_or_Configuration_Setting__w32_22_bad()
{
    char * data;
    char dataBuffer[100] = "";
    data = dataBuffer;
    CWE15_External_Control_of_System_or_Configuration_Setting__w32_22_badGlobal = 1; /* true */
    data = CWE15_External_Control_of_System_or_Configuration_Setting__w32_22_badSource(data);
    /* POTENTIAL FLAW: set the hostname to data obtained from a potentially external source */
    if (!SetComputerNameA(data))
    {
        printLine("Failure setting computer name");
        exit(1);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* The global variables below are used to drive control flow in the source functions. */
int CWE15_External_Control_of_System_or_Configuration_Setting__w32_22_goodG2B1Global = 0;
int CWE15_External_Control_of_System_or_Configuration_Setting__w32_22_goodG2B2Global = 0;

/* goodG2B1() - use goodsource and badsink by setting the static variable to false instead of true */
char * CWE15_External_Control_of_System_or_Configuration_Setting__w32_22_goodG2B1Source(char * data);

static void goodG2B1()
{
    char * data;
    char dataBuffer[100] = "";
    data = dataBuffer;
    CWE15_External_Control_of_System_or_Configuration_Setting__w32_22_goodG2B1Global = 0; /* false */
    data = CWE15_External_Control_of_System_or_Configuration_Setting__w32_22_goodG2B1Source(data);
    /* POTENTIAL FLAW: set the hostname to data obtained from a potentially external source */
    if (!SetComputerNameA(data))
    {
        printLine("Failure setting computer name");
        exit(1);
    }
}

/* goodG2B2() - use goodsource and badsink by reversing the blocks in the if in the source function */
char * CWE15_External_Control_of_System_or_Configuration_Setting__w32_22_goodG2B2Source(char * data);

static void goodG2B2()
{
    char * data;
    char dataBuffer[100] = "";
    data = dataBuffer;
    CWE15_External_Control_of_System_or_Configuration_Setting__w32_22_goodG2B2Global = 1; /* true */
    data = CWE15_External_Control_of_System_or_Configuration_Setting__w32_22_goodG2B2Source(data);
    /* POTENTIAL FLAW: set the hostname to data obtained from a potentially external source */
    if (!SetComputerNameA(data))
    {
        printLine("Failure setting computer name");
        exit(1);
    }
}

void CWE15_External_Control_of_System_or_Configuration_Setting__w32_22_good()
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
    CWE15_External_Control_of_System_or_Configuration_Setting__w32_22_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE15_External_Control_of_System_or_Configuration_Setting__w32_22_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
