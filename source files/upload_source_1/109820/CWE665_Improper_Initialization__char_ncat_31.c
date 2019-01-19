/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE665_Improper_Initialization__char_ncat_31.c
Label Definition File: CWE665_Improper_Initialization.label.xml
Template File: sources-sink-31.tmpl.c
*/
/*
 * @description
 * CWE: 665 Improper Initialization
 * BadSource:  Do not initialize data properly
 * GoodSource: Initialize data
 * Sinks: ncat
 *    BadSink : Copy string to data using strncat
 * Flow Variant: 31 Data flow using a copy of data within the same function
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

void CWE665_Improper_Initialization__char_ncat_31_bad()
{
    char * data;
    char dataBuffer[100];
    data = dataBuffer;
    /* FLAW: Do not initialize data */
    ; /* empty statement needed for some flow variants */
    {
        char * dataCopy = data;
        char * data = dataCopy;
        {
            size_t sourceLen;
            char source[100];
            memset(source, 'C', 100-1); /* fill with 'C's */
            source[100-1] = '\0'; /* null terminate */
            sourceLen = strlen(source);
            /* POTENTIAL FLAW: If data is not initialized properly, strncat() may not function correctly */
            strncat(data, source, sourceLen);
            printLine(data);
        }
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B() uses the GoodSource with the BadSink */
static void goodG2B()
{
    char * data;
    char dataBuffer[100];
    data = dataBuffer;
    /* FIX: Properly initialize data */
    data[0] = '\0'; /* null terminate */
    {
        char * dataCopy = data;
        char * data = dataCopy;
        {
            size_t sourceLen;
            char source[100];
            memset(source, 'C', 100-1); /* fill with 'C's */
            source[100-1] = '\0'; /* null terminate */
            sourceLen = strlen(source);
            /* POTENTIAL FLAW: If data is not initialized properly, strncat() may not function correctly */
            strncat(data, source, sourceLen);
            printLine(data);
        }
    }
}

void CWE665_Improper_Initialization__char_ncat_31_good()
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
    CWE665_Improper_Initialization__char_ncat_31_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE665_Improper_Initialization__char_ncat_31_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
