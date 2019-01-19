/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE134_Uncontrolled_Format_String__char_file_printf_68b.c
Label Definition File: CWE134_Uncontrolled_Format_String.label.xml
Template File: sources-sinks-68b.tmpl.c
*/
/*
 * @description
 * CWE: 134 Uncontrolled Format String
 * BadSource: file Read input from a file
 * GoodSource: Copy a fixed string into data
 * Sinks: printf
 *    GoodSink: printf with "%s" as the first argument and data as the second
 *    BadSink : printf with only data as an argument
 * Flow Variant: 68 Data flow: data passed as a global variable from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#ifndef _WIN32
#include <wchar.h>
#endif

#ifdef _WIN32
#define FILENAME "C:\\temp\\file.txt"
#else
#define FILENAME "/tmp/file.txt"
#endif

extern char * CWE134_Uncontrolled_Format_String__char_file_printf_68_badData;
extern char * CWE134_Uncontrolled_Format_String__char_file_printf_68_goodG2BData;
extern char * CWE134_Uncontrolled_Format_String__char_file_printf_68_goodB2GData;

#ifndef OMITBAD

void CWE134_Uncontrolled_Format_String__char_file_printf_68b_badSink()
{
    char * data = CWE134_Uncontrolled_Format_String__char_file_printf_68_badData;
    /* POTENTIAL FLAW: Do not specify the format allowing a possible format string vulnerability */
    printf(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE134_Uncontrolled_Format_String__char_file_printf_68b_goodG2BSink()
{
    char * data = CWE134_Uncontrolled_Format_String__char_file_printf_68_goodG2BData;
    /* POTENTIAL FLAW: Do not specify the format allowing a possible format string vulnerability */
    printf(data);
}

/* goodB2G uses the BadSource with the GoodSink */
void CWE134_Uncontrolled_Format_String__char_file_printf_68b_goodB2GSink()
{
    char * data = CWE134_Uncontrolled_Format_String__char_file_printf_68_goodB2GData;
    /* FIX: Specify the format disallowing a format string vulnerability */
    printf("%s\n", data);
}

#endif /* OMITGOOD */
