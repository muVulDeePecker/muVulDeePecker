/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE78_OS_Command_Injection__char_file_execl_41.c
Label Definition File: CWE78_OS_Command_Injection.strings.label.xml
Template File: sources-sink-41.tmpl.c
*/
/*
 * @description
 * CWE: 78 OS Command Injection
 * BadSource: file Read input from a file
 * GoodSource: Fixed string
 * Sink: execl
 *    BadSink : execute command with execl
 * Flow Variant: 41 Data flow: data passed as an argument from one function to another in the same source file
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifdef _WIN32
#define COMMAND_INT_PATH "%WINDIR%\\system32\\cmd.exe"
#define COMMAND_INT "cmd.exe"
#define COMMAND_ARG1 "/c"
#define COMMAND_ARG2 "dir"
#define COMMAND_ARG3 data
#else /* NOT _WIN32 */
#include <unistd.h>
#define COMMAND_INT_PATH "/bin/sh"
#define COMMAND_INT "sh"
#define COMMAND_ARG1 "ls"
#define COMMAND_ARG2 "-la"
#define COMMAND_ARG3 data
#endif

#ifdef _WIN32
#define FILENAME "C:\\temp\\file.txt"
#else
#define FILENAME "/tmp/file.txt"
#endif

#ifdef _WIN32
#include <process.h>
#define EXECL _execl
#else /* NOT _WIN32 */
#define EXECL execl
#endif

#ifndef OMITBAD

void CWE78_OS_Command_Injection__char_file_execl_41_badSink(char * data)
{
    /* execl - specify the path where the command is located */
    /* POTENTIAL FLAW: Execute command without validating input possibly leading to command injection */
    EXECL(COMMAND_INT_PATH, COMMAND_INT_PATH, COMMAND_ARG1, COMMAND_ARG2, COMMAND_ARG3, NULL);
}

void CWE78_OS_Command_Injection__char_file_execl_41_bad()
{
    char * data;
    char dataBuffer[100] = "";
    data = dataBuffer;
    {
        /* Read input from a file */
        size_t dataLen = strlen(data);
        FILE * pFile;
        /* if there is room in data, attempt to read the input from a file */
        if (100-dataLen > 1)
        {
            pFile = fopen(FILENAME, "r");
            if (pFile != NULL)
            {
                /* POTENTIAL FLAW: Read data from a file */
                if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL)
                {
                    printLine("fgets() failed");
                    /* Restore NUL terminator if fgets fails */
                    data[dataLen] = '\0';
                }
                fclose(pFile);
            }
        }
    }
    CWE78_OS_Command_Injection__char_file_execl_41_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

void CWE78_OS_Command_Injection__char_file_execl_41_goodG2BSink(char * data)
{
    /* execl - specify the path where the command is located */
    /* POTENTIAL FLAW: Execute command without validating input possibly leading to command injection */
    EXECL(COMMAND_INT_PATH, COMMAND_INT_PATH, COMMAND_ARG1, COMMAND_ARG2, COMMAND_ARG3, NULL);
}

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B()
{
    char * data;
    char dataBuffer[100] = "";
    data = dataBuffer;
    /* FIX: Append a fixed string to data (not user / external input) */
    strcat(data, "*.*");
    CWE78_OS_Command_Injection__char_file_execl_41_goodG2BSink(data);
}

void CWE78_OS_Command_Injection__char_file_execl_41_good()
{
    goodG2B();
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
    CWE78_OS_Command_Injection__char_file_execl_41_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE78_OS_Command_Injection__char_file_execl_41_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
