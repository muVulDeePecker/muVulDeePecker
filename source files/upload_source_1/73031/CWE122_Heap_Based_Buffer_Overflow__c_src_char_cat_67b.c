/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__c_src_char_cat_67b.c
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__c_src.label.xml
Template File: sources-sink-67b.tmpl.c
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Initialize data as a large string
 * GoodSource: Initialize data as a small string
 * Sinks: cat
 *    BadSink : Copy data to string using strcat
 * Flow Variant: 67 Data flow: data passed in a struct from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

typedef struct _CWE122_Heap_Based_Buffer_Overflow__c_src_char_cat_67_structType
{
    char * structFirst;
} CWE122_Heap_Based_Buffer_Overflow__c_src_char_cat_67_structType;

#ifndef OMITBAD

void CWE122_Heap_Based_Buffer_Overflow__c_src_char_cat_67b_badSink(CWE122_Heap_Based_Buffer_Overflow__c_src_char_cat_67_structType myStruct)
{
    char * data = myStruct.structFirst;
    {
        char dest[50] = "";
        /* POTENTIAL FLAW: Possible buffer overflow if data is larger than sizeof(dest)-strlen(dest)*/
        strcat(dest, data);
        printLine(data);
        free(data);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE122_Heap_Based_Buffer_Overflow__c_src_char_cat_67b_goodG2BSink(CWE122_Heap_Based_Buffer_Overflow__c_src_char_cat_67_structType myStruct)
{
    char * data = myStruct.structFirst;
    {
        char dest[50] = "";
        /* POTENTIAL FLAW: Possible buffer overflow if data is larger than sizeof(dest)-strlen(dest)*/
        strcat(dest, data);
        printLine(data);
        free(data);
    }
}

#endif /* OMITGOOD */
