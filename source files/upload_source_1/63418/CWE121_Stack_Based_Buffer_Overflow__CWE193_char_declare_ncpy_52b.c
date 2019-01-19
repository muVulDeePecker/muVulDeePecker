/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_ncpy_52b.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE193.label.xml
Template File: sources-sink-52b.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * BadSource:  Point data to a buffer that does not have space for a NULL terminator
 * GoodSource: Point data to a buffer that includes space for a NULL terminator
 * Sink: ncpy
 *    BadSink : Copy string to data using strncpy()
 * Flow Variant: 52 Data flow: data passed as an argument from one function to another to another in three different source files
 *
 * */

#include "std_testcase.h"

#ifndef _WIN32
#include <wchar.h>
#endif

/* MAINTENANCE NOTE: The length of this string should equal the 10 */
#define SRC_STRING "AAAAAAAAAA"

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

#ifndef OMITBAD

/* bad function declaration */
void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_ncpy_52c_badSink(char * data);

void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_ncpy_52b_badSink(char * data)
{
    CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_ncpy_52c_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good function declaration */
void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_ncpy_52c_goodG2BSink(char * data);

/* goodG2B uses the GoodSource with the BadSink */
void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_ncpy_52b_goodG2BSink(char * data)
{
    CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_ncpy_52c_goodG2BSink(data);
}

#endif /* OMITGOOD */
