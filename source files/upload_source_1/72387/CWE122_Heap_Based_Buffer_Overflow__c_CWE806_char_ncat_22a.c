/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__c_CWE806_char_ncat_22a.c
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__c_CWE806.label.xml
Template File: sources-sink-22a.tmpl.c
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Initialize data as a large string
 * GoodSource: Initialize data as a small string
 * Sink: ncat
 *    BadSink : Copy data to string using strncat
 * Flow Variant: 22 Control flow: Flow controlled by value of a global variable. Sink functions are in a separate file from sources.
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

/* The global variable below is used to drive control flow in the source function */
int CWE122_Heap_Based_Buffer_Overflow__c_CWE806_char_ncat_22_badGlobal = 0;

char * CWE122_Heap_Based_Buffer_Overflow__c_CWE806_char_ncat_22_badSource(char * data);

void CWE122_Heap_Based_Buffer_Overflow__c_CWE806_char_ncat_22_bad()
{
    char * data;
    data = (char *)malloc(100*sizeof(char));
    CWE122_Heap_Based_Buffer_Overflow__c_CWE806_char_ncat_22_badGlobal = 1; /* true */
    data = CWE122_Heap_Based_Buffer_Overflow__c_CWE806_char_ncat_22_badSource(data);
    {
        char dest[50] = "";
        /* POTENTIAL FLAW: Possible buffer overflow if data is larger than sizeof(dest)-strlen(dest)*/
        strncat(dest, data, strlen(data));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
        free(data);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* The global variables below are used to drive control flow in the source functions. */
int CWE122_Heap_Based_Buffer_Overflow__c_CWE806_char_ncat_22_goodG2B1Global = 0;
int CWE122_Heap_Based_Buffer_Overflow__c_CWE806_char_ncat_22_goodG2B2Global = 0;

/* goodG2B1() - use goodsource and badsink by setting the static variable to false instead of true */
char * CWE122_Heap_Based_Buffer_Overflow__c_CWE806_char_ncat_22_goodG2B1Source(char * data);

static void goodG2B1()
{
    char * data;
    data = (char *)malloc(100*sizeof(char));
    CWE122_Heap_Based_Buffer_Overflow__c_CWE806_char_ncat_22_goodG2B1Global = 0; /* false */
    data = CWE122_Heap_Based_Buffer_Overflow__c_CWE806_char_ncat_22_goodG2B1Source(data);
    {
        char dest[50] = "";
        /* POTENTIAL FLAW: Possible buffer overflow if data is larger than sizeof(dest)-strlen(dest)*/
        strncat(dest, data, strlen(data));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
        free(data);
    }
}

/* goodG2B2() - use goodsource and badsink by reversing the blocks in the if in the source function */
char * CWE122_Heap_Based_Buffer_Overflow__c_CWE806_char_ncat_22_goodG2B2Source(char * data);

static void goodG2B2()
{
    char * data;
    data = (char *)malloc(100*sizeof(char));
    CWE122_Heap_Based_Buffer_Overflow__c_CWE806_char_ncat_22_goodG2B2Global = 1; /* true */
    data = CWE122_Heap_Based_Buffer_Overflow__c_CWE806_char_ncat_22_goodG2B2Source(data);
    {
        char dest[50] = "";
        /* POTENTIAL FLAW: Possible buffer overflow if data is larger than sizeof(dest)-strlen(dest)*/
        strncat(dest, data, strlen(data));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
        free(data);
    }
}

void CWE122_Heap_Based_Buffer_Overflow__c_CWE806_char_ncat_22_good()
{
    goodG2B1();
    goodG2B2();
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
    CWE122_Heap_Based_Buffer_Overflow__c_CWE806_char_ncat_22_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE122_Heap_Based_Buffer_Overflow__c_CWE806_char_ncat_22_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
