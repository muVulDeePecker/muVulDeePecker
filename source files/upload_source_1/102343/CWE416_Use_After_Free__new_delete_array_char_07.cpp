/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE416_Use_After_Free__new_delete_array_char_07.cpp
Label Definition File: CWE416_Use_After_Free__new_delete_array.label.xml
Template File: sources-sinks-07.tmpl.cpp
*/
/*
 * @description
 * CWE: 416 Use After Free
 * BadSource:  Allocate data using new, initialize memory block, and Deallocate data using delete
 * GoodSource: Allocate data using new and initialize memory block
 * Sinks:
 *    GoodSink: Do nothing
 *    BadSink : Use data after delete[]
 * Flow Variant: 07 Control flow: if(staticFive==5) and if(staticFive!=5)
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

/* The variable below is not declared "const", but is never assigned
   any other value so a tool should be able to identify that reads of
   this will always give its initialized value. */
static int staticFive = 5;

namespace CWE416_Use_After_Free__new_delete_array_char_07
{

#ifndef OMITBAD

void bad()
{
    char * data;
    /* Initialize data */
    data = NULL;
    if(staticFive==5)
    {
        data = new char[100];
        memset(data, 'A', 100-1);
        data[100-1] = '\0';
        /* POTENTIAL FLAW: Delete data in the source - the bad sink attempts to use data */
        delete [] data;
    }
    if(staticFive==5)
    {
        /* POTENTIAL FLAW: Use of data that may have been deleted */
        printLine(data);
        /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not deleted */
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G1() - use badsource and goodsink by changing the second staticFive==5 to staticFive!=5 */
static void goodB2G1()
{
    char * data;
    /* Initialize data */
    data = NULL;
    if(staticFive==5)
    {
        data = new char[100];
        memset(data, 'A', 100-1);
        data[100-1] = '\0';
        /* POTENTIAL FLAW: Delete data in the source - the bad sink attempts to use data */
        delete [] data;
    }
    if(staticFive!=5)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        /* FIX: Don't use data that may have been deleted already */
        /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not deleted */
        /* do nothing */
        ; /* empty statement needed for some flow variants */
    }
}

/* goodB2G2() - use badsource and goodsink by reversing the blocks in the second if */
static void goodB2G2()
{
    char * data;
    /* Initialize data */
    data = NULL;
    if(staticFive==5)
    {
        data = new char[100];
        memset(data, 'A', 100-1);
        data[100-1] = '\0';
        /* POTENTIAL FLAW: Delete data in the source - the bad sink attempts to use data */
        delete [] data;
    }
    if(staticFive==5)
    {
        /* FIX: Don't use data that may have been deleted already */
        /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not deleted */
        /* do nothing */
        ; /* empty statement needed for some flow variants */
    }
}

/* goodG2B1() - use goodsource and badsink by changing the first staticFive==5 to staticFive!=5 */
static void goodG2B1()
{
    char * data;
    /* Initialize data */
    data = NULL;
    if(staticFive!=5)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        data = new char[100];
        memset(data, 'A', 100-1);
        data[100-1] = '\0';
        /* FIX: Do not delete data in the source */
    }
    if(staticFive==5)
    {
        /* POTENTIAL FLAW: Use of data that may have been deleted */
        printLine(data);
        /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not deleted */
    }
}

/* goodG2B2() - use goodsource and badsink by reversing the blocks in the first if */
static void goodG2B2()
{
    char * data;
    /* Initialize data */
    data = NULL;
    if(staticFive==5)
    {
        data = new char[100];
        memset(data, 'A', 100-1);
        data[100-1] = '\0';
        /* FIX: Do not delete data in the source */
    }
    if(staticFive==5)
    {
        /* POTENTIAL FLAW: Use of data that may have been deleted */
        printLine(data);
        /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not deleted */
    }
}

void good()
{
    goodB2G1();
    goodB2G2();
    goodG2B1();
    goodG2B2();
}

#endif /* OMITGOOD */

} /* close namespace */

/* Below is the main(). It is only used when building this testcase on
   its own for testing or for building a binary to use in testing binary
   analysis tools. It is not used when compiling all the testcases as one
   application, which is how source code analysis tools are tested. */

#ifdef INCLUDEMAIN

using namespace CWE416_Use_After_Free__new_delete_array_char_07; /* so that we can use good and bad easily */

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
