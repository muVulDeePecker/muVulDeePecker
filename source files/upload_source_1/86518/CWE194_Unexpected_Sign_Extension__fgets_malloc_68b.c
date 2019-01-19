/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE194_Unexpected_Sign_Extension__fgets_malloc_68b.c
Label Definition File: CWE194_Unexpected_Sign_Extension.label.xml
Template File: sources-sink-68b.tmpl.c
*/
/*
 * @description
 * CWE: 194 Unexpected Sign Extension
 * BadSource: fgets Read data from the console using fgets()
 * GoodSource: Positive integer
 * Sink: malloc
 *    BadSink : Allocate memory using malloc() with the size of data
 * Flow Variant: 68 Data flow: data passed as a global variable from one function to another in different source files
 *
 * */

#include "std_testcase.h"

/* Must be at least 8 for atoi() to work properly */
#define CHAR_ARRAY_SIZE 8

extern short CWE194_Unexpected_Sign_Extension__fgets_malloc_68_badData;
extern short CWE194_Unexpected_Sign_Extension__fgets_malloc_68_goodG2BData;

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

#ifndef OMITBAD

void CWE194_Unexpected_Sign_Extension__fgets_malloc_68b_badSink()
{
    short data = CWE194_Unexpected_Sign_Extension__fgets_malloc_68_badData;
    /* Assume we want to allocate a relatively small buffer */
    if (data < 100)
    {
        /* POTENTIAL FLAW: malloc() takes a size_t (unsigned int) as input and therefore if it is negative,
         * the conversion will cause malloc() to allocate a very large amount of data or fail */
        char * dataBuffer = (char *)malloc(data);
        /* Do something with dataBuffer */
        memset(dataBuffer, 'A', data-1);
        dataBuffer[data-1] = '\0';
        printLine(dataBuffer);
        free(dataBuffer);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE194_Unexpected_Sign_Extension__fgets_malloc_68b_goodG2BSink()
{
    short data = CWE194_Unexpected_Sign_Extension__fgets_malloc_68_goodG2BData;
    /* Assume we want to allocate a relatively small buffer */
    if (data < 100)
    {
        /* POTENTIAL FLAW: malloc() takes a size_t (unsigned int) as input and therefore if it is negative,
         * the conversion will cause malloc() to allocate a very large amount of data or fail */
        char * dataBuffer = (char *)malloc(data);
        /* Do something with dataBuffer */
        memset(dataBuffer, 'A', data-1);
        dataBuffer[data-1] = '\0';
        printLine(dataBuffer);
        free(dataBuffer);
    }
}

#endif /* OMITGOOD */
