/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__c_CWE129_fgets_84_goodB2G.cpp
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__c_CWE129.label.xml
Template File: sources-sinks-84_goodB2G.tmpl.cpp
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource: fgets Read data from the console using fgets()
 * GoodSource: Larger than zero but less than 10
 * Sinks:
 *    GoodSink: Ensure the array index is valid
 *    BadSink : Improperly check the array index by not checking the upper bound
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */
#ifndef OMITGOOD

#include "std_testcase.h"
#include "CWE122_Heap_Based_Buffer_Overflow__c_CWE129_fgets_84.h"

#define CHAR_ARRAY_SIZE (3 * sizeof(data) + 2)

namespace CWE122_Heap_Based_Buffer_Overflow__c_CWE129_fgets_84
{
CWE122_Heap_Based_Buffer_Overflow__c_CWE129_fgets_84_goodB2G::CWE122_Heap_Based_Buffer_Overflow__c_CWE129_fgets_84_goodB2G(int dataCopy)
{
    data = dataCopy;
    {
        char inputBuffer[CHAR_ARRAY_SIZE] = "";
        /* POTENTIAL FLAW: Read data from the console using fgets() */
        if (fgets(inputBuffer, CHAR_ARRAY_SIZE, stdin) != NULL)
        {
            /* Convert to int */
            data = atoi(inputBuffer);
        }
        else
        {
            printLine("fgets() failed.");
        }
    }
}

CWE122_Heap_Based_Buffer_Overflow__c_CWE129_fgets_84_goodB2G::~CWE122_Heap_Based_Buffer_Overflow__c_CWE129_fgets_84_goodB2G()
{
    {
        int i;
        int * buffer = (int *)malloc(10 * sizeof(int));
        /* initialize buffer */
        for (i = 0; i < 10; i++)
        {
            buffer[i] = 0;
        }
        /* FIX: Properly validate the array index and prevent a buffer overflow */
        if (data >= 0 && data < (10))
        {
            buffer[data] = 1;
            /* Print the array values */
            for(i = 0; i < 10; i++)
            {
                printIntLine(buffer[i]);
            }
        }
        else
        {
            printLine("ERROR: Array index is out-of-bounds");
        }
        free(buffer);
    }
}
}
#endif /* OMITGOOD */
