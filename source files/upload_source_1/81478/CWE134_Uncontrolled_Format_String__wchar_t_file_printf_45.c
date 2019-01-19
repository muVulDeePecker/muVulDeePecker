/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE134_Uncontrolled_Format_String__wchar_t_file_printf_45.c
Label Definition File: CWE134_Uncontrolled_Format_String.label.xml
Template File: sources-sinks-45.tmpl.c
*/
/*
 * @description
 * CWE: 134 Uncontrolled Format String
 * BadSource: file Read input from a file
 * GoodSource: Copy a fixed string into data
 * Sinks: printf
 *    GoodSink: wprintf with "%s" as the first argument and data as the second
 *    BadSink : wprintf with only data as an argument
 * Flow Variant: 45 Data flow: data passed as a static global variable from one function to another in the same source file
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

static wchar_t * CWE134_Uncontrolled_Format_String__wchar_t_file_printf_45_badData;
static wchar_t * CWE134_Uncontrolled_Format_String__wchar_t_file_printf_45_goodG2BData;
static wchar_t * CWE134_Uncontrolled_Format_String__wchar_t_file_printf_45_goodB2GData;

#ifndef OMITBAD

static void badSink()
{
    wchar_t * data = CWE134_Uncontrolled_Format_String__wchar_t_file_printf_45_badData;
    /* POTENTIAL FLAW: Do not specify the format allowing a possible format string vulnerability */
    wprintf(data);
}

void CWE134_Uncontrolled_Format_String__wchar_t_file_printf_45_bad()
{
    wchar_t * data;
    wchar_t dataBuffer[100] = L"";
    data = dataBuffer;
    {
        /* Read input from a file */
        size_t dataLen = wcslen(data);
        FILE * pFile;
        /* if there is room in data, attempt to read the input from a file */
        if (100-dataLen > 1)
        {
            pFile = fopen(FILENAME, "r");
            if (pFile != NULL)
            {
                /* POTENTIAL FLAW: Read data from a file */
                if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL)
                {
                    printLine("fgetws() failed");
                    /* Restore NUL terminator if fgetws fails */
                    data[dataLen] = L'\0';
                }
                fclose(pFile);
            }
        }
    }
    CWE134_Uncontrolled_Format_String__wchar_t_file_printf_45_badData = data;
    badSink();
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B() uses the GoodSource with the BadSink */
static void goodG2BSink()
{
    wchar_t * data = CWE134_Uncontrolled_Format_String__wchar_t_file_printf_45_goodG2BData;
    /* POTENTIAL FLAW: Do not specify the format allowing a possible format string vulnerability */
    wprintf(data);
}

static void goodG2B()
{
    wchar_t * data;
    wchar_t dataBuffer[100] = L"";
    data = dataBuffer;
    /* FIX: Use a fixed string that does not contain a format specifier */
    wcscpy(data, L"fixedstringtest");
    CWE134_Uncontrolled_Format_String__wchar_t_file_printf_45_goodG2BData = data;
    goodG2BSink();
}

/* goodB2G() uses the BadSource with the GoodSink */
static void goodB2GSink()
{
    wchar_t * data = CWE134_Uncontrolled_Format_String__wchar_t_file_printf_45_goodB2GData;
    /* FIX: Specify the format disallowing a format string vulnerability */
    wprintf(L"%s\n", data);
}

static void goodB2G()
{
    wchar_t * data;
    wchar_t dataBuffer[100] = L"";
    data = dataBuffer;
    {
        /* Read input from a file */
        size_t dataLen = wcslen(data);
        FILE * pFile;
        /* if there is room in data, attempt to read the input from a file */
        if (100-dataLen > 1)
        {
            pFile = fopen(FILENAME, "r");
            if (pFile != NULL)
            {
                /* POTENTIAL FLAW: Read data from a file */
                if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL)
                {
                    printLine("fgetws() failed");
                    /* Restore NUL terminator if fgetws fails */
                    data[dataLen] = L'\0';
                }
                fclose(pFile);
            }
        }
    }
    CWE134_Uncontrolled_Format_String__wchar_t_file_printf_45_goodB2GData = data;
    goodB2GSink();
}

void CWE134_Uncontrolled_Format_String__wchar_t_file_printf_45_good()
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
    CWE134_Uncontrolled_Format_String__wchar_t_file_printf_45_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE134_Uncontrolled_Format_String__wchar_t_file_printf_45_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
