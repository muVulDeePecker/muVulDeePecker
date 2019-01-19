/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE127_Buffer_Underread__malloc_char_memmove_32.c
Label Definition File: CWE127_Buffer_Underread__malloc.label.xml
Template File: sources-sink-32.tmpl.c
*/
/*
 * @description
 * CWE: 127 Buffer Under-read
 * BadSource:  Set data pointer to before the allocated memory buffer
 * GoodSource: Set data pointer to the allocated memory buffer
 * Sink: memmove
 *    BadSink : Copy data to string using memmove
 * Flow Variant: 32 Data flow using two pointers to the same value within the same function
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

void CWE127_Buffer_Underread__malloc_char_memmove_32_bad()
{
    char * data;
    char * *dataPtr1 = &data;
    char * *dataPtr2 = &data;
    data = NULL;
    {
        char * data = *dataPtr1;
        {
            char * dataBuffer = (char *)malloc(100*sizeof(char));
            memset(dataBuffer, 'A', 100-1);
            dataBuffer[100-1] = '\0';
            /* FLAW: Set data pointer to before the allocated memory buffer */
            data = dataBuffer - 8;
        }
        *dataPtr1 = data;
    }
    {
        char * data = *dataPtr2;
        {
            char dest[100];
            memset(dest, 'C', 100-1); /* fill with 'C's */
            dest[100-1] = '\0'; /* null terminate */
            /* POTENTIAL FLAW: Possibly copy from a memory location located before the source buffer */
            memmove(dest, data, 100*sizeof(char));
            /* Ensure null termination */
            dest[100-1] = '\0';
            printLine(dest);
            /* INCIDENTAL CWE-401: Memory Leak - data may not point to location
             * returned by malloc() so can't safely call free() on it */
        }
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B() uses the GoodSource with the BadSink */
static void goodG2B()
{
    char * data;
    char * *dataPtr1 = &data;
    char * *dataPtr2 = &data;
    data = NULL;
    {
        char * data = *dataPtr1;
        {
            char * dataBuffer = (char *)malloc(100*sizeof(char));
            memset(dataBuffer, 'A', 100-1);
            dataBuffer[100-1] = '\0';
            /* FIX: Set data pointer to the allocated memory buffer */
            data = dataBuffer;
        }
        *dataPtr1 = data;
    }
    {
        char * data = *dataPtr2;
        {
            char dest[100];
            memset(dest, 'C', 100-1); /* fill with 'C's */
            dest[100-1] = '\0'; /* null terminate */
            /* POTENTIAL FLAW: Possibly copy from a memory location located before the source buffer */
            memmove(dest, data, 100*sizeof(char));
            /* Ensure null termination */
            dest[100-1] = '\0';
            printLine(dest);
            /* INCIDENTAL CWE-401: Memory Leak - data may not point to location
             * returned by malloc() so can't safely call free() on it */
        }
    }
}

void CWE127_Buffer_Underread__malloc_char_memmove_32_good()
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
    CWE127_Buffer_Underread__malloc_char_memmove_32_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE127_Buffer_Underread__malloc_char_memmove_32_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
