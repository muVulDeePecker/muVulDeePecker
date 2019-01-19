/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_fixed_string_84a.cpp
Label Definition File: CWE761_Free_Pointer_Not_at_Start_of_Buffer.label.xml
Template File: source-sinks-84a.tmpl.cpp
*/
/*
 * @description
 * CWE: 761 Free Pointer not at Start of Buffer
 * BadSource: fixed_string Initialize data to be a fixed string
 * Sinks:
 *    GoodSink: free() memory correctly at the start of the buffer
 *    BadSink : free() memory not at the start of the buffer
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */

#include "std_testcase.h"
#include "CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_fixed_string_84.h"

namespace CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_fixed_string_84
{

#ifndef OMITBAD

void bad()
{
    char * data;
    data = (char *)malloc(100*sizeof(char));
    data[0] = '\0';
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_fixed_string_84_bad * badObject = new CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_fixed_string_84_bad(data);
    delete badObject;
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G uses the BadSource with the GoodSink */
static void goodB2G()
{
    char * data;
    data = (char *)malloc(100*sizeof(char));
    data[0] = '\0';
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_fixed_string_84_goodB2G * goodB2GObject = new CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_fixed_string_84_goodB2G(data);
    delete goodB2GObject;
}

void good()
{
    goodB2G();
}

#endif /* OMITGOOD */

} /* close namespace */

/* Below is the main(). It is only used when building this testcase on
   its own for testing or for building a binary to use in testing binary
   analysis tools. It is not used when compiling all the testcases as one
   application, which is how source code analysis tools are tested. */

#ifdef INCLUDEMAIN

using namespace CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_fixed_string_84; /* so that we can use good and bad easily */

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
