/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE195_Signed_to_Unsigned_Conversion_Error__fscanf_strncpy_65a.c
Label Definition File: CWE195_Signed_to_Unsigned_Conversion_Error.label.xml
Template File: sources-sink-65a.tmpl.c
*/
/*
 * @description
 * CWE: 195 Signed to Unsigned Conversion Error
 * BadSource: fscanf Read data from the console using fscanf()
 * GoodSource: Positive integer
 * Sinks: strncpy
 *    BadSink : Copy strings using strncpy() with the length of data
 * Flow Variant: 65 Data/control flow: data passed as an argument from one function to a function in a different source file called via a function pointer
 *
 * */

#include "std_testcase.h"

#ifndef OMITBAD

/* bad function declaration */
void CWE195_Signed_to_Unsigned_Conversion_Error__fscanf_strncpy_65b_badSink(int data);

void CWE195_Signed_to_Unsigned_Conversion_Error__fscanf_strncpy_65_bad()
{
    int data;
    /* define a function pointer */
    void (*funcPtr) (int) = CWE195_Signed_to_Unsigned_Conversion_Error__fscanf_strncpy_65b_badSink;
    /* Initialize data */
    data = -1;
    /* POTENTIAL FLAW: Read data from the console using fscanf() */
    fscanf(stdin, "%d", &data);
    /* use the function pointer */
    funcPtr(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE195_Signed_to_Unsigned_Conversion_Error__fscanf_strncpy_65b_goodG2BSink(int data);

static void goodG2B()
{
    int data;
    void (*funcPtr) (int) = CWE195_Signed_to_Unsigned_Conversion_Error__fscanf_strncpy_65b_goodG2BSink;
    /* Initialize data */
    data = -1;
    /* FIX: Use a positive integer less than &InitialDataSize&*/
    data = 100-1;
    funcPtr(data);
}

void CWE195_Signed_to_Unsigned_Conversion_Error__fscanf_strncpy_65_good()
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
    CWE195_Signed_to_Unsigned_Conversion_Error__fscanf_strncpy_65_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE195_Signed_to_Unsigned_Conversion_Error__fscanf_strncpy_65_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
