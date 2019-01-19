/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE78_OS_Command_Injection__char_environment_w32_spawnvp_84_goodG2B.cpp
Label Definition File: CWE78_OS_Command_Injection.strings.label.xml
Template File: sources-sink-84_goodG2B.tmpl.cpp
*/
/*
 * @description
 * CWE: 78 OS Command Injection
 * BadSource: environment Read input from an environment variable
 * GoodSource: Fixed string
 * Sinks: w32_spawnvp
 *    BadSink : execute command with spawnvp
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */
#ifndef OMITGOOD

#include "std_testcase.h"
#include "CWE78_OS_Command_Injection__char_environment_w32_spawnvp_84.h"

#include <process.h>

namespace CWE78_OS_Command_Injection__char_environment_w32_spawnvp_84
{
CWE78_OS_Command_Injection__char_environment_w32_spawnvp_84_goodG2B::CWE78_OS_Command_Injection__char_environment_w32_spawnvp_84_goodG2B(char * dataCopy)
{
    data = dataCopy;
    /* FIX: Append a fixed string to data (not user / external input) */
    strcat(data, "*.*");
}

CWE78_OS_Command_Injection__char_environment_w32_spawnvp_84_goodG2B::~CWE78_OS_Command_Injection__char_environment_w32_spawnvp_84_goodG2B()
{
    {
        char *args[] = {COMMAND_INT_PATH, COMMAND_ARG1, COMMAND_ARG2, COMMAND_ARG3, NULL};
        /* spawnvp - searches for the location of the command among
         * the directories specified by the PATH environment variable */
        /* POTENTIAL FLAW: Execute command without validating input possibly leading to command injection */
        _spawnvp(_P_WAIT, COMMAND_INT, args);
    }
}
}
#endif /* OMITGOOD */
