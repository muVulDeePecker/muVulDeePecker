/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__placement_new_32.cpp
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__placement_new.label.xml
Template File: sources-sinks-32.tmpl.cpp
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Initialize data to a small buffer
 * GoodSource: Initialize data to a buffer large enough to hold a TwoIntsClass
 * Sinks:
 *    GoodSink: Allocate a new class using placement new and a buffer that is large enough to hold the class
 *    BadSink : Allocate a new class using placement new and a buffer that is too small
 * Flow Variant: 32 Data flow using two pointers to the same value within the same function
 *
 * */

#include "std_testcase.h"

namespace CWE122_Heap_Based_Buffer_Overflow__placement_new_32
{

#ifndef OMITBAD

void bad()
{
    char * data;
    char * *dataPtr1 = &data;
    char * *dataPtr2 = &data;
    char * dataBadBuffer = (char *)malloc(sizeof(OneIntClass));
    char * dataGoodBuffer = (char *)malloc(sizeof(TwoIntsClass));
    {
        char * data = *dataPtr1;
        /* POTENTIAL FLAW: Initialize data to a buffer small than the sizeof(TwoIntsClass) */
        data = dataBadBuffer;
        *dataPtr1 = data;
    }
    {
        char * data = *dataPtr2;
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

/* goodG2B() uses the GoodSource with the BadSink */
static void goodG2B()
{
    char * data;
    char * *dataPtr1 = &data;
    char * *dataPtr2 = &data;
    char * dataBadBuffer = (char *)malloc(sizeof(OneIntClass));
    char * dataGoodBuffer = (char *)malloc(sizeof(TwoIntsClass));
    {
        char * data = *dataPtr1;
        /* FIX: Initialize to a buffer at least the sizeof(TwoIntsClass) */
        data = dataGoodBuffer;
        *dataPtr1 = data;
    }
    {
        char * data = *dataPtr2;
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

/* goodB2G() uses the BadSource with the GoodSink */
static void goodB2G()
{
    char * data;
    char * *dataPtr1 = &data;
    char * *dataPtr2 = &data;
    char * dataBadBuffer = (char *)malloc(sizeof(OneIntClass));
    char * dataGoodBuffer = (char *)malloc(sizeof(TwoIntsClass));
    {
        char * data = *dataPtr1;
        /* POTENTIAL FLAW: Initialize data to a buffer small than the sizeof(TwoIntsClass) */
        data = dataBadBuffer;
        *dataPtr1 = data;
    }
    {
        char * data = *dataPtr2;
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

using namespace CWE122_Heap_Based_Buffer_Overflow__placement_new_32; /* so that we can use good and bad easily */

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
