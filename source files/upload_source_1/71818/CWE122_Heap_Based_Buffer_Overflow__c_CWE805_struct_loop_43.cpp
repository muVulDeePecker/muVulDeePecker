/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__c_CWE805_struct_loop_43.cpp
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__c_CWE805.label.xml
Template File: sources-sink-43.tmpl.cpp
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Allocate using malloc() and set data pointer to a small buffer
 * GoodSource: Allocate using malloc() and set data pointer to a large buffer
 * Sinks: loop
 *    BadSink : Copy twoIntsStruct array to data using a loop
 * Flow Variant: 43 Data flow: data flows using a C++ reference from one function to another in the same source file
 *
 * */

#include "std_testcase.h"

namespace CWE122_Heap_Based_Buffer_Overflow__c_CWE805_struct_loop_43
{

#ifndef OMITBAD

static void badSource(twoIntsStruct * &data)
{
    /* FLAW: Allocate and point data to a small buffer that is smaller than the large buffer used in the sinks */
    data = (twoIntsStruct *)malloc(50*sizeof(twoIntsStruct));
}

void bad()
{
    twoIntsStruct * data;
    data = NULL;
    badSource(data);
    {
        twoIntsStruct source[100];
        {
            size_t i;
            /* Initialize array */
            for (i = 0; i < 100; i++)
            {
                source[i].intOne = 0;
                source[i].intTwo = 0;
            }
        }
        {
            size_t i;
            /* POTENTIAL FLAW: Possible buffer overflow if data < 100 */
            for (i = 0; i < 100; i++)
            {
                data[i] = source[i];
            }
            printStructLine(&data[0]);
            free(data);
        }
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B() uses the GoodSource with the BadSink */
static void goodG2BSource(twoIntsStruct * &data)
{
    /* FIX: Allocate and point data to a large buffer that is at least as large as the large buffer used in the sink */
    data = (twoIntsStruct *)malloc(100*sizeof(twoIntsStruct));
}

static void goodG2B()
{
    twoIntsStruct * data;
    data = NULL;
    goodG2BSource(data);
    {
        twoIntsStruct source[100];
        {
            size_t i;
            /* Initialize array */
            for (i = 0; i < 100; i++)
            {
                source[i].intOne = 0;
                source[i].intTwo = 0;
            }
        }
        {
            size_t i;
            /* POTENTIAL FLAW: Possible buffer overflow if data < 100 */
            for (i = 0; i < 100; i++)
            {
                data[i] = source[i];
            }
            printStructLine(&data[0]);
            free(data);
        }
    }
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

using namespace CWE122_Heap_Based_Buffer_Overflow__c_CWE805_struct_loop_43; /* so that we can use good and bad easily */

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
