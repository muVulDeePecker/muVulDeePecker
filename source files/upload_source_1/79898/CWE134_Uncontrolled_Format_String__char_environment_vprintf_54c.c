/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE134_Uncontrolled_Format_String__char_environment_vprintf_54c.c
Label Definition File: CWE134_Uncontrolled_Format_String.vasinks.label.xml
Template File: sources-vasinks-54c.tmpl.c
*/
/*
 * @description
 * CWE: 134 Uncontrolled Format String
 * BadSource: environment Read input from an environment variable
 * GoodSource: Copy a fixed string into data
 * Sinks: vprintf
 *    GoodSink: vprintf with a format string
 *    BadSink : vprintf without a format string
 * Flow Variant: 54 Data flow: data passed as an argument from one function through three others to a fifth; all five functions are in different source files
 *
 * */

#include <stdarg.h>
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

/* bad function declaration */
void CWE134_Uncontrolled_Format_String__char_environment_vprintf_54d_badSink(char * data);

void CWE134_Uncontrolled_Format_String__char_environment_vprintf_54c_badSink(char * data)
{
    CWE134_Uncontrolled_Format_String__char_environment_vprintf_54d_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE134_Uncontrolled_Format_String__char_environment_vprintf_54d_goodG2BSink(char * data);

void CWE134_Uncontrolled_Format_String__char_environment_vprintf_54c_goodG2BSink(char * data)
{
    CWE134_Uncontrolled_Format_String__char_environment_vprintf_54d_goodG2BSink(data);
}

/* goodB2G uses the BadSource with the GoodSink */
void CWE134_Uncontrolled_Format_String__char_environment_vprintf_54d_goodB2GSink(char * data);

void CWE134_Uncontrolled_Format_String__char_environment_vprintf_54c_goodB2GSink(char * data)
{
    CWE134_Uncontrolled_Format_String__char_environment_vprintf_54d_goodB2GSink(data);
}

#endif /* OMITGOOD */
