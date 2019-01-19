/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE194_Unexpected_Sign_Extension__fscanf_memmove_54a.c
Label Definition File: CWE194_Unexpected_Sign_Extension.label.xml
Template File: sources-sink-54a.tmpl.c
*/
/*
 * @description
 * CWE: 194 Unexpected Sign Extension
 * BadSource: fscanf Read data from the console using fscanf()
 * GoodSource: Positive integer
 * Sink: memmove
 *    BadSink : Copy strings using memmove() with the length of data
 * Flow Variant: 54 Data flow: data passed as an argument from one function through three others to a fifth; all five functions are in different source files
 *
 * */

#include "std_testcase.h"

#ifndef OMITBAD

/* bad function declaration */
void CWE194_Unexpected_Sign_Extension__fscanf_memmove_54b_badSink(short data);

void CWE194_Unexpected_Sign_Extension__fscanf_memmove_54_bad()
{
    short data;
    /* Initialize data */
    data = 0;
    /* FLAW: Use a value input from the console using fscanf() */
    fscanf (stdin, "%hd", &data);
    CWE194_Unexpected_Sign_Extension__fscanf_memmove_54b_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good function declaration */
void CWE194_Unexpected_Sign_Extension__fscanf_memmove_54b_goodG2BSink(short data);

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B()
{
    short data;
    /* Initialize data */
    data = 0;
    /* FIX: Use a positive integer less than &InitialDataSize&*/
    data = 100-1;
    CWE194_Unexpected_Sign_Extension__fscanf_memmove_54b_goodG2BSink(data);
}

void CWE194_Unexpected_Sign_Extension__fscanf_memmove_54_good()
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
    CWE194_Unexpected_Sign_Extension__fscanf_memmove_54_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE194_Unexpected_Sign_Extension__fscanf_memmove_54_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
