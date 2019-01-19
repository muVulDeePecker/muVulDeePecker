/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE457_Use_of_Uninitialized_Variable__struct_pointer_62a.cpp
Label Definition File: CWE457_Use_of_Uninitialized_Variable.c.label.xml
Template File: sources-sinks-62a.tmpl.cpp
*/
/*
 * @description
 * CWE: 457 Use of Uninitialized Variable
 * BadSource: no_init Don't initialize data
 * GoodSource: Initialize data
 * Sinks: use
 *    GoodSink: Initialize then use data
 *    BadSink : Use data
 * Flow Variant: 62 Data flow: data flows using a C++ reference from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

namespace CWE457_Use_of_Uninitialized_Variable__struct_pointer_62
{

#ifndef OMITBAD

/* bad function declaration */
void badSource(twoIntsStruct * &data);

void bad()
{
    twoIntsStruct * data;
    badSource(data);
    /* POTENTIAL FLAW: Use data without initializing it */
    printIntLine(data->intOne);
    printIntLine(data->intTwo);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void goodG2BSource(twoIntsStruct * &data);

static void goodG2B()
{
    twoIntsStruct * data;
    goodG2BSource(data);
    /* POTENTIAL FLAW: Use data without initializing it */
    printIntLine(data->intOne);
    printIntLine(data->intTwo);
}

/* goodB2G uses the BadSource with the GoodSink */
void goodB2GSource(twoIntsStruct * &data);

static void goodB2G()
{
    twoIntsStruct * data;
    goodB2GSource(data);
    /* FIX: Ensure data is initialized before use */
    /* initialize both the pointer and the data pointed to */
    data = (twoIntsStruct *)malloc(sizeof(twoIntsStruct));
    data->intOne = 5;
    data->intTwo = 6;
    printIntLine(data->intOne);
    printIntLine(data->intTwo);
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

using namespace CWE457_Use_of_Uninitialized_Variable__struct_pointer_62; /* so that we can use good and bad easily */

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
