/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE135_67b.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE135.label.xml
Template File: sources-sinks-67b.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * BadSource:  Void pointer to a wchar_t array
 * GoodSource: Void pointer to a char array
 * Sinks:
 *    GoodSink: Allocate memory using wcslen() and copy data
 *    BadSink : Allocate memory using strlen() and copy data
 * Flow Variant: 67 Data flow: data passed in a struct from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#define WIDE_STRING L"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
#define CHAR_STRING "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

typedef struct _CWE121_Stack_Based_Buffer_Overflow__CWE135_67_structType
{
    void * structFirst;
} CWE121_Stack_Based_Buffer_Overflow__CWE135_67_structType;

#ifndef OMITBAD

void CWE121_Stack_Based_Buffer_Overflow__CWE135_67b_badSink(CWE121_Stack_Based_Buffer_Overflow__CWE135_67_structType myStruct)
{
    void * data = myStruct.structFirst;
    {
        /* POTENTIAL FLAW: treating pointer as a char* when it may point to a wide string */
        size_t dataLen = strlen((char *)data);
        void * dest = (void *)calloc(dataLen+1, 1);
        memcpy(dest, data, (dataLen+1));
        printLine((char *)dest);
        free(dest);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE121_Stack_Based_Buffer_Overflow__CWE135_67b_goodG2BSink(CWE121_Stack_Based_Buffer_Overflow__CWE135_67_structType myStruct)
{
    void * data = myStruct.structFirst;
    {
        /* POTENTIAL FLAW: treating pointer as a char* when it may point to a wide string */
        size_t dataLen = strlen((char *)data);
        void * dest = (void *)calloc(dataLen+1, 1);
        memcpy(dest, data, (dataLen+1));
        printLine((char *)dest);
        free(dest);
    }
}

/* goodB2G uses the BadSource with the GoodSink */
void CWE121_Stack_Based_Buffer_Overflow__CWE135_67b_goodB2GSink(CWE121_Stack_Based_Buffer_Overflow__CWE135_67_structType myStruct)
{
    void * data = myStruct.structFirst;
    {
        /* FIX: treating pointer like a wchar_t*  */
        size_t dataLen = wcslen((wchar_t *)data);
        void * dest = (void *)calloc(dataLen+1, sizeof(wchar_t));
        memcpy(dest, data, (dataLen+1)*sizeof(wchar_t));
        printWLine((wchar_t *)dest);
        free(dest);
    }
}

#endif /* OMITGOOD */
