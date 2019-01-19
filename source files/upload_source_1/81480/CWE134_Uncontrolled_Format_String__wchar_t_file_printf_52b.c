/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE134_Uncontrolled_Format_String__wchar_t_file_printf_52b.c
Label Definition File: CWE134_Uncontrolled_Format_String.label.xml
Template File: sources-sinks-52b.tmpl.c
*/
/*
 * @description
 * CWE: 134 Uncontrolled Format String
 * BadSource: file Read input from a file
 * GoodSource: Copy a fixed string into data
 * Sinks: printf
 *    GoodSink: wprintf with "%s" as the first argument and data as the second
 *    BadSink : wprintf with only data as an argument
 * Flow Variant: 52 Data flow: data passed as an argument from one function to another to another in three different source files
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

#ifndef OMITBAD

/* bad function declaration */
void CWE134_Uncontrolled_Format_String__wchar_t_file_printf_52c_badSink(wchar_t * data);

void CWE134_Uncontrolled_Format_String__wchar_t_file_printf_52b_badSink(wchar_t * data)
{
    CWE134_Uncontrolled_Format_String__wchar_t_file_printf_52c_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE134_Uncontrolled_Format_String__wchar_t_file_printf_52c_goodG2BSink(wchar_t * data);

void CWE134_Uncontrolled_Format_String__wchar_t_file_printf_52b_goodG2BSink(wchar_t * data)
{
    CWE134_Uncontrolled_Format_String__wchar_t_file_printf_52c_goodG2BSink(data);
}

/* goodB2G uses the BadSource with the GoodSink */
void CWE134_Uncontrolled_Format_String__wchar_t_file_printf_52c_goodB2GSink(wchar_t * data);

void CWE134_Uncontrolled_Format_String__wchar_t_file_printf_52b_goodB2GSink(wchar_t * data)
{
    CWE134_Uncontrolled_Format_String__wchar_t_file_printf_52c_goodB2GSink(data);
}

#endif /* OMITGOOD */
