/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_ncat_81a.cpp
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__c_CWE805.string.label.xml
Template File: sources-sink-81a.tmpl.cpp
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Allocate using malloc() and set data pointer to a small buffer
 * GoodSource: Allocate using malloc() and set data pointer to a large buffer
 * Sinks: ncat
 *    BadSink : Copy string to data using strncat
 * Flow Variant: 81 Data flow: data passed in a parameter to an virtual method called via a reference
 *
 * */

#include "std_testcase.h"
#include "CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_ncat_81.h"

namespace CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_ncat_81
{

#ifndef OMITBAD

void bad()
{
    char * data;
    data = NULL;
    /* FLAW: Allocate and point data to a small buffer that is smaller than the large buffer used in the sinks */
    data = (char *)malloc(50*sizeof(char));
    data[0] = '\0'; /* null terminate */
    const CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_ncat_81_base& baseObject = CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_ncat_81_bad();
    baseObject.action(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B()
{
    char * data;
    data = NULL;
    /* FIX: Allocate and point data to a large buffer that is at least as large as the large buffer used in the sink */
    data = (char *)malloc(100*sizeof(char));
    data[0] = '\0'; /* null terminate */
    const CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_ncat_81_base& baseObject = CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_ncat_81_goodG2B();
    baseObject.action(data);
}

void good()
{
    goodG2B();
}

#endif /* OMITGOOD */

} /* close namespace */

/* Below is the main(). It is only used when building this testcase on
 * its own for testing or for building a binary to use in testing binary
 * analysis tools. It is not used when compiling all the testcases as one
 * application, which is how source code analysis tools are tested.
 */

#ifdef INCLUDEMAIN

using namespace CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_ncat_81; /* so that we can use good and bad easily */

int main(int argc, char * argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
    printLine("Calling good()...");
    good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
