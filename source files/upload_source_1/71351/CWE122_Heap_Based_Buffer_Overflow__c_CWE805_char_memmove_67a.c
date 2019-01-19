/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_67a.c
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__c_CWE805.string.label.xml
Template File: sources-sink-67a.tmpl.c
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Allocate using malloc() and set data pointer to a small buffer
 * GoodSource: Allocate using malloc() and set data pointer to a large buffer
 * Sinks: memmove
 *    BadSink : Copy string to data using memmove
 * Flow Variant: 67 Data flow: data passed in a struct from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

typedef struct _CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_67_structType
{
    char * structFirst;
} CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_67_structType;

#ifndef OMITBAD

/* bad function declaration */
void CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_67b_badSink(CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_67_structType myStruct);

void CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_67_bad()
{
    char * data;
    CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_67_structType myStruct;
    data = NULL;
    /* FLAW: Allocate and point data to a small buffer that is smaller than the large buffer used in the sinks */
    data = (char *)malloc(50*sizeof(char));
    data[0] = '\0'; /* null terminate */
    myStruct.structFirst = data;
    CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_67b_badSink(myStruct);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_67b_goodG2BSink(CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_67_structType myStruct);

static void goodG2B()
{
    char * data;
    CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_67_structType myStruct;
    data = NULL;
    /* FIX: Allocate and point data to a large buffer that is at least as large as the large buffer used in the sink */
    data = (char *)malloc(100*sizeof(char));
    data[0] = '\0'; /* null terminate */
    myStruct.structFirst = data;
    CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_67b_goodG2BSink(myStruct);
}

void CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_67_good()
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
    CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_67_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_67_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
