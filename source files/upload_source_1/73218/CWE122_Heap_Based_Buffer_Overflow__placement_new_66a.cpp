/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__placement_new_66a.cpp
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__placement_new.label.xml
Template File: sources-sinks-66a.tmpl.cpp
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Initialize data to a small buffer
 * GoodSource: Initialize data to a buffer large enough to hold a TwoIntsClass
 * Sinks:
 *    GoodSink: Allocate a new class using placement new and a buffer that is large enough to hold the class
 *    BadSink : Allocate a new class using placement new and a buffer that is too small
 * Flow Variant: 66 Data flow: data passed in an array from one function to another in different source files
 *
 * */

#include "std_testcase.h"

namespace CWE122_Heap_Based_Buffer_Overflow__placement_new_66
{

#ifndef OMITBAD

/* bad function declaration */
void badSink(char * dataArray[]);

void bad()
{
    char * data;
    char * dataArray[5];
    char * dataBadBuffer = (char *)malloc(sizeof(OneIntClass));
    char * dataGoodBuffer = (char *)malloc(sizeof(TwoIntsClass));
    /* POTENTIAL FLAW: Initialize data to a buffer small than the sizeof(TwoIntsClass) */
    data = dataBadBuffer;
    /* put data in array */
    dataArray[2] = data;
    badSink(dataArray);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void goodG2BSink(char * dataArray[]);

static void goodG2B()
{
    char * data;
    char * dataArray[5];
    char * dataBadBuffer = (char *)malloc(sizeof(OneIntClass));
    char * dataGoodBuffer = (char *)malloc(sizeof(TwoIntsClass));
    /* FIX: Initialize to a buffer at least the sizeof(TwoIntsClass) */
    data = dataGoodBuffer;
    dataArray[2] = data;
    goodG2BSink(dataArray);
}

/* goodB2G uses the BadSource with the GoodSink */
void goodB2GSink(char * dataArray[]);

static void goodB2G()
{
    char * data;
    char * dataArray[5];
    char * dataBadBuffer = (char *)malloc(sizeof(OneIntClass));
    char * dataGoodBuffer = (char *)malloc(sizeof(TwoIntsClass));
    /* POTENTIAL FLAW: Initialize data to a buffer small than the sizeof(TwoIntsClass) */
    data = dataBadBuffer;
    dataArray[2] = data;
    goodB2GSink(dataArray);
}

void good()
{
    goodG2B();
    goodB2G();
}

#endif /* OMITGOOD */

} /* close namespace */

/* Below is the main(). It is only used when building this testcase on
   its own for testing or for building a binary to use in testing binary
   analysis tools. It is not used when compiling all the testcases as one
   application, which is how source code analysis tools are tested. */

#ifdef INCLUDEMAIN

using namespace CWE122_Heap_Based_Buffer_Overflow__placement_new_66; /* so that we can use good and bad easily */

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
