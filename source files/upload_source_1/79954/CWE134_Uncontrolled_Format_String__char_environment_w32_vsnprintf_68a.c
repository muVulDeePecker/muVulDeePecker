/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE134_Uncontrolled_Format_String__char_environment_w32_vsnprintf_68a.c
Label Definition File: CWE134_Uncontrolled_Format_String.vasinks.label.xml
Template File: sources-vasinks-68a.tmpl.c
*/
/*
 * @description
 * CWE: 134 Uncontrolled Format String
 * BadSource: environment Read input from an environment variable
 * GoodSource: Copy a fixed string into data
 * Sinks: w32_vsnprintf
 *    GoodSink: vsnprintf with a format string
 *    BadSink : vsnprintf without a format string
 * Flow Variant: 68 Data flow: data passed as a global variable from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#ifndef _WIN32
#include <wchar.h>
#endif

#define ENV_VARIABLE "ADD"

#ifdef _WIN32
#define GETENV getenv
#else
#define GETENV getenv
#endif

char * CWE134_Uncontrolled_Format_String__char_environment_w32_vsnprintf_68_badData;
char * CWE134_Uncontrolled_Format_String__char_environment_w32_vsnprintf_68_goodG2BData;
char * CWE134_Uncontrolled_Format_String__char_environment_w32_vsnprintf_68_goodB2GData;

#ifndef OMITBAD

/* bad function declaration */
void CWE134_Uncontrolled_Format_String__char_environment_w32_vsnprintf_68b_badSink();

void CWE134_Uncontrolled_Format_String__char_environment_w32_vsnprintf_68_bad()
{
    char * data;
    char dataBuffer[100] = "";
    data = dataBuffer;
    {
        /* Append input from an environment variable to data */
        size_t dataLen = strlen(data);
        char * environment = GETENV(ENV_VARIABLE);
        /* If there is data in the environment variable */
        if (environment != NULL)
        {
            /* POTENTIAL FLAW: Read data from an environment variable */
            strncat(data+dataLen, environment, 100-dataLen-1);
        }
    }
    CWE134_Uncontrolled_Format_String__char_environment_w32_vsnprintf_68_badData = data;
    CWE134_Uncontrolled_Format_String__char_environment_w32_vsnprintf_68b_badSink();
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good function declarations */
void CWE134_Uncontrolled_Format_String__char_environment_w32_vsnprintf_68b_goodG2BSink();
void CWE134_Uncontrolled_Format_String__char_environment_w32_vsnprintf_68b_goodB2GSink();

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B()
{
    char * data;
    char dataBuffer[100] = "";
    data = dataBuffer;
    /* FIX: Use a fixed string that does not contain a format specifier */
    strcpy(data, "fixedstringtest");
    CWE134_Uncontrolled_Format_String__char_environment_w32_vsnprintf_68_goodG2BData = data;
    CWE134_Uncontrolled_Format_String__char_environment_w32_vsnprintf_68b_goodG2BSink();
}

/* goodB2G uses the BadSource with the GoodSink */
static void goodB2G()
{
    char * data;
    char dataBuffer[100] = "";
    data = dataBuffer;
    {
        /* Append input from an environment variable to data */
        size_t dataLen = strlen(data);
        char * environment = GETENV(ENV_VARIABLE);
        /* If there is data in the environment variable */
        if (environment != NULL)
        {
            /* POTENTIAL FLAW: Read data from an environment variable */
            strncat(data+dataLen, environment, 100-dataLen-1);
        }
    }
    CWE134_Uncontrolled_Format_String__char_environment_w32_vsnprintf_68_goodB2GData = data;
    CWE134_Uncontrolled_Format_String__char_environment_w32_vsnprintf_68b_goodB2GSink();
}

void CWE134_Uncontrolled_Format_String__char_environment_w32_vsnprintf_68_good()
{
    goodG2B();
    goodB2G();
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
    CWE134_Uncontrolled_Format_String__char_environment_w32_vsnprintf_68_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE134_Uncontrolled_Format_String__char_environment_w32_vsnprintf_68_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
