/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE400_Resource_Exhaustion__connect_socket_fwrite_83a.cpp
Label Definition File: CWE400_Resource_Exhaustion.label.xml
Template File: sources-sinks-83a.tmpl.cpp
*/
/*
 * @description
 * CWE: 400 Resource Exhaustion
 * BadSource: connect_socket Read data using a connect socket (client side)
 * GoodSource: Assign count to be a relatively small number
 * Sinks: fwrite
 *    GoodSink: Write to a file count number of times, but first validate count
 *    BadSink : Write to a file count number of times
 * Flow Variant: 83 Data flow: data passed to class constructor and destructor by declaring the class object on the stack
 *
 * */

#include "std_testcase.h"
#include "CWE400_Resource_Exhaustion__connect_socket_fwrite_83.h"

namespace CWE400_Resource_Exhaustion__connect_socket_fwrite_83
{

#ifndef OMITBAD

void bad()
{
    int count;
    /* Initialize count */
    count = -1;
    CWE400_Resource_Exhaustion__connect_socket_fwrite_83_bad badObject(count);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B()
{
    int count;
    /* Initialize count */
    count = -1;
    CWE400_Resource_Exhaustion__connect_socket_fwrite_83_goodG2B goodG2BObject(count);
}

/* goodG2B uses the BadSource with the GoodSink */
static void goodB2G()
{
    int count;
    /* Initialize count */
    count = -1;
    CWE400_Resource_Exhaustion__connect_socket_fwrite_83_goodB2G goodB2GObject(count);
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

using namespace CWE400_Resource_Exhaustion__connect_socket_fwrite_83; /* so that we can use good and bad easily */

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
