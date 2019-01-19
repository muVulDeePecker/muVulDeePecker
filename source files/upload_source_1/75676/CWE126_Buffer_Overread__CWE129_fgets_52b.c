/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE126_Buffer_Overread__CWE129_fgets_52b.c
Label Definition File: CWE126_Buffer_Overread__CWE129.label.xml
Template File: sources-sinks-52b.tmpl.c
*/
/*
 * @description
 * CWE: 126 Buffer Overread
 * BadSource: fgets Read data from the console using fgets()
 * GoodSource: Larger than zero but less than 10
 * Sinks:
 *    GoodSink: Ensure the array index is valid
 *    BadSink : Improperly check the array index by not checking the upper bound
 * Flow Variant: 52 Data flow: data passed as an argument from one function to another to another in three different source files
 *
 * */

#include "std_testcase.h"

#define CHAR_ARRAY_SIZE (3 * sizeof(data) + 2)

#ifndef OMITBAD

/* bad function declaration */
void CWE126_Buffer_Overread__CWE129_fgets_52c_badSink(int data);

void CWE126_Buffer_Overread__CWE129_fgets_52b_badSink(int data)
{
    CWE126_Buffer_Overread__CWE129_fgets_52c_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE126_Buffer_Overread__CWE129_fgets_52c_goodG2BSink(int data);

void CWE126_Buffer_Overread__CWE129_fgets_52b_goodG2BSink(int data)
{
    CWE126_Buffer_Overread__CWE129_fgets_52c_goodG2BSink(data);
}

/* goodB2G uses the BadSource with the GoodSink */
void CWE126_Buffer_Overread__CWE129_fgets_52c_goodB2GSink(int data);

void CWE126_Buffer_Overread__CWE129_fgets_52b_goodB2GSink(int data)
{
    CWE126_Buffer_Overread__CWE129_fgets_52c_goodB2GSink(data);
}

#endif /* OMITGOOD */
