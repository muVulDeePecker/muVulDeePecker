/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE134_Uncontrolled_Format_String__char_file_vfprintf_65a.c
Label Definition File: CWE134_Uncontrolled_Format_String.vasinks.label.xml
Template File: sources-vasinks-65a.tmpl.c
*/
/*
 * @description
 * CWE: 134 Uncontrolled Format String
 * BadSource: file Read input from a file
 * GoodSource: Copy a fixed string into data
 * Sinks: vfprintf
 *    GoodSink: vfprintf with a format string
 *    BadSink : vfprintf without a format string
 * Flow Variant: 65 Data/control flow: data passed as an argument from one function to a function in a different source file called via a function pointer
 *
 * */

#include <stdarg.h>
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
void CWE134_Uncontrolled_Format_String__char_file_vfprintf_65b_badVaSink(char * data, ...);

void CWE134_Uncontrolled_Format_String__char_file_vfprintf_65_bad()
{
    char * data;
    /* define a function pointer */
    void (*funcPtr) (char *, ...) = CWE134_Uncontrolled_Format_String__char_file_vfprintf_65b_badVaSink;
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
    /* use the function pointer */
    funcPtr(data, data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE134_Uncontrolled_Format_String__char_file_vfprintf_65b_goodG2BVaSink(char * data, ...);

static void goodG2B()
{
    char * data;
    void (*funcPtr) (char *, ...) = CWE134_Uncontrolled_Format_String__char_file_vfprintf_65b_goodG2BVaSink;
    char dataBuffer[100] = "";
    data = dataBuffer;
    /* FIX: Use a fixed string that does not contain a format specifier */
    strcpy(data, "fixedstringtest");
    funcPtr(data);
}

/* goodB2G uses the BadSource with the GoodSink */
void CWE134_Uncontrolled_Format_String__char_file_vfprintf_65b_goodB2GVaSink(char * data, ...);

static void goodB2G()
{
    char * data;
    void (*funcPtr) (char *, ...) = CWE134_Uncontrolled_Format_String__char_file_vfprintf_65b_goodB2GVaSink;
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
    funcPtr(data);
}

void CWE134_Uncontrolled_Format_String__char_file_vfprintf_65_good()
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
    CWE134_Uncontrolled_Format_String__char_file_vfprintf_65_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE134_Uncontrolled_Format_String__char_file_vfprintf_65_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
