/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE464_Addition_of_Data_Structure_Sentinel__basic_54c.c
Label Definition File: CWE464_Addition_of_Data_Structure_Sentinel__basic.label.xml
Template File: sources-sink-54c.tmpl.c
*/
/*
 * @description
 * CWE: 464 Addition of Data Structure Sentinel
 * BadSource:  Read in data from the console and convert to an int
 * GoodSource: Set data to a fixed char
 * Sink:
 *    BadSink : Place data into and print an array
 * Flow Variant: 54 Data flow: data passed as an argument from one function through three others to a fifth; all five functions are in different source files
 *
 * */

#include "std_testcase.h"

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

#ifndef OMITBAD

/* bad function declaration */
void CWE464_Addition_of_Data_Structure_Sentinel__basic_54d_badSink(char data);

void CWE464_Addition_of_Data_Structure_Sentinel__basic_54c_badSink(char data)
{
    CWE464_Addition_of_Data_Structure_Sentinel__basic_54d_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good function declaration */
void CWE464_Addition_of_Data_Structure_Sentinel__basic_54d_goodG2BSink(char data);

/* goodG2B uses the GoodSource with the BadSink */
void CWE464_Addition_of_Data_Structure_Sentinel__basic_54c_goodG2BSink(char data)
{
    CWE464_Addition_of_Data_Structure_Sentinel__basic_54d_goodG2BSink(data);
}

#endif /* OMITGOOD */
