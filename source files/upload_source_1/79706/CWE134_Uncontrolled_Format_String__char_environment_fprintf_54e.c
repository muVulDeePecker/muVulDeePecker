/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE134_Uncontrolled_Format_String__char_environment_fprintf_54e.c
Label Definition File: CWE134_Uncontrolled_Format_String.label.xml
Template File: sources-sinks-54e.tmpl.c
*/
/*
 * @description
 * CWE: 134 Uncontrolled Format String
 * BadSource: environment Read input from an environment variable
 * GoodSource: Copy a fixed string into data
 * Sinks: fprintf
 *    GoodSink: fprintf with "%s" as the second argument and data as the third
 *    BadSink : fprintf with data as the second argument
 * Flow Variant: 54 Data flow: data passed as an argument from one function through three others to a fifth; all five functions are in different source files
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

#ifndef OMITBAD

void CWE134_Uncontrolled_Format_String__char_environment_fprintf_54e_badSink(char * data)
{
    /* POTENTIAL FLAW: Do not specify the format allowing a possible format string vulnerability */
    fprintf(stdout, data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE134_Uncontrolled_Format_String__char_environment_fprintf_54e_goodG2BSink(char * data)
{
    /* POTENTIAL FLAW: Do not specify the format allowing a possible format string vulnerability */
    fprintf(stdout, data);
}

/* goodB2G uses the BadSource with the GoodSink */
void CWE134_Uncontrolled_Format_String__char_environment_fprintf_54e_goodB2GSink(char * data)
{
    /* FIX: Specify the format disallowing a format string vulnerability */
    fprintf(stdout, "%s\n", data);
}

#endif /* OMITGOOD */
