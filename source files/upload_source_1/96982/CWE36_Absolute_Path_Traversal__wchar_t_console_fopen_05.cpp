/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE36_Absolute_Path_Traversal__wchar_t_console_fopen_05.cpp
Label Definition File: CWE36_Absolute_Path_Traversal.label.xml
Template File: sources-sink-05.tmpl.cpp
*/
/*
 * @description
 * CWE: 36 Absolute Path Traversal
 * BadSource: console Read input from the console
 * GoodSource: Full path and file name
 * Sink: fopen
 *    BadSink : Open the file named in data using fopen()
 * Flow Variant: 05 Control flow: if(staticTrue) and if(staticFalse)
 *
 * */

#include "std_testcase.h"

#ifndef _WIN32
#include <wchar.h>
#endif

#ifdef _WIN32
#define FOPEN _wfopen
#else
#define FOPEN fopen
#endif

/* The two variables below are not defined as "const", but are never
   assigned any other value, so a tool should be able to identify that
   reads of these will always return their initialized values. */
static int staticTrue = 1; /* true */
static int staticFalse = 0; /* false */

namespace CWE36_Absolute_Path_Traversal__wchar_t_console_fopen_05
{

#ifndef OMITBAD

void bad()
{
    wchar_t * data;
    wchar_t dataBuffer[FILENAME_MAX] = L"";
    data = dataBuffer;
    if(staticTrue)
    {
        {
            /* Read input from the console */
            size_t dataLen = wcslen(data);
            /* if there is room in data, read into it from the console */
            if (FILENAME_MAX-dataLen > 1)
            {
                /* POTENTIAL FLAW: Read data from the console */
                if (fgetws(data+dataLen, (int)(FILENAME_MAX-dataLen), stdin) != NULL)
                {
                    /* The next few lines remove the carriage return from the string that is
                     * inserted by fgetws() */
                    dataLen = wcslen(data);
                    if (dataLen > 0 && data[dataLen-1] == L'\n')
                    {
                        data[dataLen-1] = L'\0';
                    }
                }
                else
                {
                    printLine("fgetws() failed");
                    /* Restore NUL terminator if fgetws fails */
                    data[dataLen] = L'\0';
                }
            }
        }
    }
    {
        FILE *pFile = NULL;
        /* POTENTIAL FLAW: Possibly opening a file without validating the file name or path */
        pFile = FOPEN(data, L"wb+");
        if (pFile != NULL)
        {
            fclose(pFile);
        }
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B1() - use goodsource and badsink by changing the staticTrue to staticFalse */
static void goodG2B1()
{
    wchar_t * data;
    wchar_t dataBuffer[FILENAME_MAX] = L"";
    data = dataBuffer;
    if(staticFalse)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
#ifdef _WIN32
        /* FIX: Use a fixed, full path and file name */
        wcscat(data, L"c:\\temp\\file.txt");
#else
        /* FIX: Use a fixed, full path and file name */
        wcscat(data, L"/tmp/file.txt");
#endif
    }
    {
        FILE *pFile = NULL;
        /* POTENTIAL FLAW: Possibly opening a file without validating the file name or path */
        pFile = FOPEN(data, L"wb+");
        if (pFile != NULL)
        {
            fclose(pFile);
        }
    }
}

/* goodG2B2() - use goodsource and badsink by reversing the blocks in the if statement */
static void goodG2B2()
{
    wchar_t * data;
    wchar_t dataBuffer[FILENAME_MAX] = L"";
    data = dataBuffer;
    if(staticTrue)
    {
#ifdef _WIN32
        /* FIX: Use a fixed, full path and file name */
        wcscat(data, L"c:\\temp\\file.txt");
#else
        /* FIX: Use a fixed, full path and file name */
        wcscat(data, L"/tmp/file.txt");
#endif
    }
    {
        FILE *pFile = NULL;
        /* POTENTIAL FLAW: Possibly opening a file without validating the file name or path */
        pFile = FOPEN(data, L"wb+");
        if (pFile != NULL)
        {
            fclose(pFile);
        }
    }
}

void good()
{
    goodG2B1();
    goodG2B2();
}

#endif /* OMITGOOD */

} /* close namespace */

/* Below is the main(). It is only used when building this testcase on
   its own for testing or for building a binary to use in testing binary
   analysis tools. It is not used when compiling all the testcases as one
   application, which is how source code analysis tools are tested. */

#ifdef INCLUDEMAIN

using namespace CWE36_Absolute_Path_Traversal__wchar_t_console_fopen_05; /* so that we can use good and bad easily */

int main(int argc, char * argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
    printLine("Calling good()...");
    good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
