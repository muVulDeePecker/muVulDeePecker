/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE401_Memory_Leak__new_array_char_68a.cpp
Label Definition File: CWE401_Memory_Leak__new_array.label.xml
Template File: sources-sinks-68a.tmpl.cpp
*/
/*
 * @description
 * CWE: 401 Memory Leak
 * BadSource:  Allocate data using new[]
 * GoodSource: Point data to a stack buffer
 * Sinks:
 *    GoodSink: call delete[] on data
 *    BadSink : no deallocation of data
 * Flow Variant: 68 Data flow: data passed as a global variable from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#ifndef _WIN32
#include <wchar.h>
#endif

namespace CWE401_Memory_Leak__new_array_char_68
{

char * badData;
char * goodG2BData;
char * goodB2GData;

#ifndef OMITBAD

/* bad function declaration */
void badSink();

void bad()
{
    char * data;
    data = NULL;
    /* POTENTIAL FLAW: Allocate memory on the heap */
    data = new char[100];
    /* Initialize and make use of data */
    strcpy(data, "A String");
    printLine(data);
    badData = data;
    badSink();
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good function declarations */
void goodG2BSink();
void goodB2GSink();

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B()
{
    char * data;
    data = NULL;
    /* FIX: Use memory allocated on the stack */
    char dataGoodBuffer[100];
    data = dataGoodBuffer;
    /* Initialize and make use of data */
    strcpy(data, "A String");
    printLine(data);
    goodG2BData = data;
    goodG2BSink();
}

/* goodB2G uses the BadSource with the GoodSink */
static void goodB2G()
{
    char * data;
    data = NULL;
    /* POTENTIAL FLAW: Allocate memory on the heap */
    data = new char[100];
    /* Initialize and make use of data */
    strcpy(data, "A String");
    printLine(data);
    goodB2GData = data;
    goodB2GSink();
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

using namespace CWE401_Memory_Leak__new_array_char_68; /* so that we can use good and bad easily */

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
