/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE131_memmove_82a.cpp
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE131.label.xml
Template File: sources-sink-82a.tmpl.cpp
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * BadSource:  Allocate memory without using sizeof(int)
 * GoodSource: Allocate memory using sizeof(int)
 * Sinks: memmove
 *    BadSink : Copy array to data using memmove()
 * Flow Variant: 82 Data flow: data passed in a parameter to an virtual method called via a pointer
 *
 * */

#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE131_memmove_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE131_memmove_82
{

#ifndef OMITBAD

void bad()
{
    int * data;
    data = NULL;
    /* FLAW: Allocate memory without using sizeof(int) */
    data = (int *)ALLOCA(10);
    CWE121_Stack_Based_Buffer_Overflow__CWE131_memmove_82_base* baseObject = new CWE121_Stack_Based_Buffer_Overflow__CWE131_memmove_82_bad;
    baseObject->action(data);
    delete baseObject;
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B()
{
    int * data;
    data = NULL;
    /* FIX: Allocate memory using sizeof(int) */
    data = (int *)ALLOCA(10*sizeof(int));
    CWE121_Stack_Based_Buffer_Overflow__CWE131_memmove_82_base* baseObject = new CWE121_Stack_Based_Buffer_Overflow__CWE131_memmove_82_goodG2B;
    baseObject->action(data);
    delete baseObject;
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

using namespace CWE121_Stack_Based_Buffer_Overflow__CWE131_memmove_82; /* so that we can use good and bad easily */

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
