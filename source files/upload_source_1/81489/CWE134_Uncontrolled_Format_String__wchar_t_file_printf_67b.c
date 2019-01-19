/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE134_Uncontrolled_Format_String__wchar_t_file_printf_67b.c
Label Definition File: CWE134_Uncontrolled_Format_String.label.xml
Template File: sources-sinks-67b.tmpl.c
*/
/*
 * @description
 * CWE: 134 Uncontrolled Format String
 * BadSource: file Read input from a file
 * GoodSource: Copy a fixed string into data
 * Sinks: printf
 *    GoodSink: wprintf with "%s" as the first argument and data as the second
 *    BadSink : wprintf with only data as an argument
 * Flow Variant: 67 Data flow: data passed in a struct from one function to another in different source files
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

typedef struct _CWE134_Uncontrolled_Format_String__wchar_t_file_printf_67_structType
{
    wchar_t * structFirst;
} CWE134_Uncontrolled_Format_String__wchar_t_file_printf_67_structType;

#ifndef OMITBAD

void CWE134_Uncontrolled_Format_String__wchar_t_file_printf_67b_badSink(CWE134_Uncontrolled_Format_String__wchar_t_file_printf_67_structType myStruct)
{
    wchar_t * data = myStruct.structFirst;
    /* POTENTIAL FLAW: Do not specify the format allowing a possible format string vulnerability */
    wprintf(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE134_Uncontrolled_Format_String__wchar_t_file_printf_67b_goodG2BSink(CWE134_Uncontrolled_Format_String__wchar_t_file_printf_67_structType myStruct)
{
    wchar_t * data = myStruct.structFirst;
    /* POTENTIAL FLAW: Do not specify the format allowing a possible format string vulnerability */
    wprintf(data);
}

/* goodB2G uses the BadSource with the GoodSink */
void CWE134_Uncontrolled_Format_String__wchar_t_file_printf_67b_goodB2GSink(CWE134_Uncontrolled_Format_String__wchar_t_file_printf_67_structType myStruct)
{
    wchar_t * data = myStruct.structFirst;
    /* FIX: Specify the format disallowing a format string vulnerability */
    wprintf(L"%s\n", data);
}

#endif /* OMITGOOD */
