/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__placement_new_17.cpp
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__placement_new.label.xml
Template File: sources-sinks-17.tmpl.cpp
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Initialize data to a small buffer
 * GoodSource: Initialize data to a buffer large enough to hold a TwoIntsClass
 * Sinks:
 *    GoodSink: Allocate a new class using placement new and a buffer that is large enough to hold the class
 *    BadSink : Allocate a new class using placement new and a buffer that is too small
 * Flow Variant: 17 Control flow: for loops
 * */

#include "std_testcase.h"

namespace CWE122_Heap_Based_Buffer_Overflow__placement_new_17
{

#ifndef OMITBAD

void bad()
{
    int i,j;
    char * data;
    char * dataBadBuffer = (char *)malloc(sizeof(OneIntClass));
    char * dataGoodBuffer = (char *)malloc(sizeof(TwoIntsClass));
    for(i = 0; i < 1; i++)
    {
        /* POTENTIAL FLAW: Initialize data to a buffer small than the sizeof(TwoIntsClass) */
        data = dataBadBuffer;
    }
    for(j = 0; j < 1; j++)
    {
        {
            /* The Visual C++ compiler generates a warning if you initialize the class with ().
             * This will cause the compile to default-initialize the object.
             * See http://msdn.microsoft.com/en-us/library/wewb47ee%28v=VS.100%29.aspx
             */
            /* POTENTIAL FLAW: data may not be large enough to hold a TwoIntsClass */
            TwoIntsClass * classTwo = new(data) TwoIntsClass;
            /* Initialize and make use of the class */
            classTwo->intOne = 5;
            classTwo->intTwo = 10; /* POTENTIAL FLAW: If sizeof(data) < sizeof(TwoIntsClass) then this line will be a buffer overflow */
            printIntLine(classTwo->intOne);
            /* skip printing classTwo->intTwo since that could be a buffer overread */
            free(data);
        }
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G() - use badsource and goodsink in the for statements */
static void goodB2G()
{
    int i,k;
    char * data;
    char * dataBadBuffer = (char *)malloc(sizeof(OneIntClass));
    char * dataGoodBuffer = (char *)malloc(sizeof(TwoIntsClass));
    for(i = 0; i < 1; i++)
    {
        /* POTENTIAL FLAW: Initialize data to a buffer small than the sizeof(TwoIntsClass) */
        data = dataBadBuffer;
    }
    for(k = 0; k < 1; k++)
    {
        {
            /* The Visual C++ compiler generates a warning if you initialize the class with ().
             * This will cause the compile to default-initialize the object.
             * See http://msdn.microsoft.com/en-us/library/wewb47ee%28v=VS.100%29.aspx
             */
            /* FIX: data will at least be the sizeof(OneIntClass) */
            OneIntClass * classOne = new(data) OneIntClass;
            /* Initialize and make use of the class */
            classOne->intOne = 5;
            printIntLine(classOne->intOne);
            free(data);
        }
    }
}

/* goodG2B() - use goodsource and badsink in the for statements */
static void goodG2B()
{
    int h,j;
    char * data;
    char * dataBadBuffer = (char *)malloc(sizeof(OneIntClass));
    char * dataGoodBuffer = (char *)malloc(sizeof(TwoIntsClass));
    for(h = 0; h < 1; h++)
    {
        /* FIX: Initialize to a buffer at least the sizeof(TwoIntsClass) */
        data = dataGoodBuffer;
    }
    for(j = 0; j < 1; j++)
    {
        {
            /* The Visual C++ compiler generates a warning if you initialize the class with ().
             * This will cause the compile to default-initialize the object.
             * See http://msdn.microsoft.com/en-us/library/wewb47ee%28v=VS.100%29.aspx
             */
            /* POTENTIAL FLAW: data may not be large enough to hold a TwoIntsClass */
            TwoIntsClass * classTwo = new(data) TwoIntsClass;
            /* Initialize and make use of the class */
            classTwo->intOne = 5;
            classTwo->intTwo = 10; /* POTENTIAL FLAW: If sizeof(data) < sizeof(TwoIntsClass) then this line will be a buffer overflow */
            printIntLine(classTwo->intOne);
            /* skip printing classTwo->intTwo since that could be a buffer overread */
            free(data);
        }
    }
}

void good()
{
    goodB2G();
    goodG2B();
}

#endif /* OMITGOOD */

} /* close namespace */

/* Below is the main(). It is only used when building this testcase on
   its own for testing or for building a binary to use in testing binary
   analysis tools. It is not used when compiling all the testcases as one
   application, which is how source code analysis tools are tested. */

#ifdef INCLUDEMAIN

using namespace CWE122_Heap_Based_Buffer_Overflow__placement_new_17; /* so that we can use good and bad easily */

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
