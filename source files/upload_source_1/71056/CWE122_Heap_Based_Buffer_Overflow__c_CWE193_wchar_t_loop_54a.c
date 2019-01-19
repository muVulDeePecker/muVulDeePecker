/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__c_CWE193_wchar_t_loop_54a.c
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__c_CWE193.label.xml
Template File: sources-sink-54a.tmpl.c
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Allocate memory for a string, but do not allocate space for NULL terminator
 * GoodSource: Allocate enough memory for a string and the NULL terminator
 * Sink: loop
 *    BadSink : Copy array to data using a loop
 * Flow Variant: 54 Data flow: data passed as an argument from one function through three others to a fifth; all five functions are in different source files
 *
 * */

#include "std_testcase.h"

#ifndef _WIN32
#include <wchar.h>
#endif

/* MAINTENANCE NOTE: The length of this string should equal the 10 */
#define SRC_STRING L"AAAAAAAAAA"

#ifndef OMITBAD

/* bad function declaration */
void CWE122_Heap_Based_Buffer_Overflow__c_CWE193_wchar_t_loop_54b_badSink(wchar_t * data);

void CWE122_Heap_Based_Buffer_Overflow__c_CWE193_wchar_t_loop_54_bad()
{
    wchar_t * data;
    data = NULL;
    /* FLAW: Did not leave space for a null terminator */
    data = (wchar_t *)malloc(10*sizeof(wchar_t));
    CWE122_Heap_Based_Buffer_Overflow__c_CWE193_wchar_t_loop_54b_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good function declaration */
void CWE122_Heap_Based_Buffer_Overflow__c_CWE193_wchar_t_loop_54b_goodG2BSink(wchar_t * data);

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B()
{
    wchar_t * data;
    data = NULL;
    /* FIX: Allocate space for a null terminator */
    data = (wchar_t *)malloc((10+1)*sizeof(wchar_t));
    CWE122_Heap_Based_Buffer_Overflow__c_CWE193_wchar_t_loop_54b_goodG2BSink(data);
}

void CWE122_Heap_Based_Buffer_Overflow__c_CWE193_wchar_t_loop_54_good()
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
    CWE122_Heap_Based_Buffer_Overflow__c_CWE193_wchar_t_loop_54_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE122_Heap_Based_Buffer_Overflow__c_CWE193_wchar_t_loop_54_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
