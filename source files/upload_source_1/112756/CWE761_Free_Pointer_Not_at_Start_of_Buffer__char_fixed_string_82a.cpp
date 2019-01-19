/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_fixed_string_82a.cpp
Label Definition File: CWE761_Free_Pointer_Not_at_Start_of_Buffer.label.xml
Template File: source-sinks-82a.tmpl.cpp
*/
/*
 * @description
 * CWE: 761 Free Pointer not at Start of Buffer
 * BadSource: fixed_string Initialize data to be a fixed string
 * Sinks:
 *    GoodSink: free() memory correctly at the start of the buffer
 *    BadSink : free() memory not at the start of the buffer
 * Flow Variant: 82 Data flow: data passed in a parameter to an virtual method called via a pointer
 *
 * */

#include "std_testcase.h"
#include "CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_fixed_string_82.h"

#define BAD_SOURCE_FIXED_STRING "Fixed String" /* MAINTENANCE NOTE: This string must contain the SEARCH_CHAR */

#define SEARCH_CHAR 'S'

namespace CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_fixed_string_82
{

#ifndef OMITBAD

void bad()
{
    char * data;
    data = (char *)malloc(100*sizeof(char));
    data[0] = '\0';
    /* POTENTIAL FLAW: Initialize data to be a fixed string that contains the search character in the sinks */
    strcpy(data, BAD_SOURCE_FIXED_STRING);
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_fixed_string_82_base* baseObject = new CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_fixed_string_82_bad;
    baseObject->action(data);
    delete baseObject;
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G uses the BadSource with the GoodSink */
static void goodB2G()
{
    char * data;
    data = (char *)malloc(100*sizeof(char));
    data[0] = '\0';
    /* POTENTIAL FLAW: Initialize data to be a fixed string that contains the search character in the sinks */
    strcpy(data, BAD_SOURCE_FIXED_STRING);
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_fixed_string_82_base* baseObject = new CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_fixed_string_82_goodB2G;
    baseObject->action(data);
    delete baseObject;
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

using namespace CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_fixed_string_82; /* so that we can use good and bad easily */

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
