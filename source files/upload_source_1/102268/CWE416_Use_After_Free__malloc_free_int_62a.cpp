/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE416_Use_After_Free__malloc_free_int_62a.cpp
Label Definition File: CWE416_Use_After_Free__malloc_free.label.xml
Template File: sources-sinks-62a.tmpl.cpp
*/
/*
 * @description
 * CWE: 416 Use After Free
 * BadSource:  Allocate data using malloc(), initialize memory block, and Deallocate data using free()
 * GoodSource: Allocate data using malloc() and initialize memory block
 * Sinks:
 *    GoodSink: Do nothing
 *    BadSink : Use data
 * Flow Variant: 62 Data flow: data flows using a C++ reference from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

namespace CWE416_Use_After_Free__malloc_free_int_62
{

#ifndef OMITBAD

/* bad function declaration */
void badSource(int * &data);

void bad()
{
    int * data;
    /* Initialize data */
    data = NULL;
    badSource(data);
    /* POTENTIAL FLAW: Use of data that may have been freed */
    printIntLine(data[0]);
    /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not freed */
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void goodG2BSource(int * &data);

static void goodG2B()
{
    int * data;
    /* Initialize data */
    data = NULL;
    goodG2BSource(data);
    /* POTENTIAL FLAW: Use of data that may have been freed */
    printIntLine(data[0]);
    /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not freed */
}

/* goodB2G uses the BadSource with the GoodSink */
void goodB2GSource(int * &data);

static void goodB2G()
{
    int * data;
    /* Initialize data */
    data = NULL;
    goodB2GSource(data);
    /* FIX: Don't use data that may have been freed already */
    /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not freed */
    /* do nothing */
    ; /* empty statement needed for some flow variants */
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

using namespace CWE416_Use_After_Free__malloc_free_int_62; /* so that we can use good and bad easily */

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
