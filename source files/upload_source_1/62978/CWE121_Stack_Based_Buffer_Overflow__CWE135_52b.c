/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE135_52b.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE135.label.xml
Template File: sources-sinks-52b.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * BadSource:  Void pointer to a wchar_t array
 * GoodSource: Void pointer to a char array
 * Sinks:
 *    GoodSink: Allocate memory using wcslen() and copy data
 *    BadSink : Allocate memory using strlen() and copy data
 * Flow Variant: 52 Data flow: data passed as an argument from one function to another to another in three different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#define WIDE_STRING L"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
#define CHAR_STRING "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

#ifndef OMITBAD

/* bad function declaration */
void CWE121_Stack_Based_Buffer_Overflow__CWE135_52c_badSink(void * data);

void CWE121_Stack_Based_Buffer_Overflow__CWE135_52b_badSink(void * data)
{
    CWE121_Stack_Based_Buffer_Overflow__CWE135_52c_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE121_Stack_Based_Buffer_Overflow__CWE135_52c_goodG2BSink(void * data);

void CWE121_Stack_Based_Buffer_Overflow__CWE135_52b_goodG2BSink(void * data)
{
    CWE121_Stack_Based_Buffer_Overflow__CWE135_52c_goodG2BSink(data);
}

/* goodB2G uses the BadSource with the GoodSink */
void CWE121_Stack_Based_Buffer_Overflow__CWE135_52c_goodB2GSink(void * data);

void CWE121_Stack_Based_Buffer_Overflow__CWE135_52b_goodB2GSink(void * data)
{
    CWE121_Stack_Based_Buffer_Overflow__CWE135_52c_goodB2GSink(data);
}

#endif /* OMITGOOD */
