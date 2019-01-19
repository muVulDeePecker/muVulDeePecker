/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE369_Divide_by_Zero__int_fgets_divide_54b.c
Label Definition File: CWE369_Divide_by_Zero__int.label.xml
Template File: sources-sinks-54b.tmpl.c
*/
/*
 * @description
 * CWE: 369 Divide by Zero
 * BadSource: fgets Read data from the console using fgets()
 * GoodSource: Non-zero
 * Sinks: divide
 *    GoodSink: Check for zero before dividing
 *    BadSink : Divide a constant by data
 * Flow Variant: 54 Data flow: data passed as an argument from one function through three others to a fifth; all five functions are in different source files
 *
 * */

#include "std_testcase.h"

#define CHAR_ARRAY_SIZE (3 * sizeof(data) + 2)

#ifndef OMITBAD

/* bad function declaration */
void CWE369_Divide_by_Zero__int_fgets_divide_54c_badSink(int data);

void CWE369_Divide_by_Zero__int_fgets_divide_54b_badSink(int data)
{
    CWE369_Divide_by_Zero__int_fgets_divide_54c_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE369_Divide_by_Zero__int_fgets_divide_54c_goodG2BSink(int data);

void CWE369_Divide_by_Zero__int_fgets_divide_54b_goodG2BSink(int data)
{
    CWE369_Divide_by_Zero__int_fgets_divide_54c_goodG2BSink(data);
}

/* goodB2G uses the BadSource with the GoodSink */
void CWE369_Divide_by_Zero__int_fgets_divide_54c_goodB2GSink(int data);

void CWE369_Divide_by_Zero__int_fgets_divide_54b_goodB2GSink(int data)
{
    CWE369_Divide_by_Zero__int_fgets_divide_54c_goodB2GSink(data);
}

#endif /* OMITGOOD */
