/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE789_Uncontrolled_Mem_Alloc__new_char_fscanf_68a.cpp
Label Definition File: CWE789_Uncontrolled_Mem_Alloc__new.label.xml
Template File: sources-sinks-68a.tmpl.cpp
*/
/*
 * @description
 * CWE: 789 Uncontrolled Memory Allocation
 * BadSource: fscanf Read data from the console using fscanf()
 * GoodSource: Small number greater than zero
 * Sinks:
 *    GoodSink: Allocate memory with new [] and check the size of the memory to be allocated
 *    BadSink : Allocate memory with new [], but incorrectly check the size of the memory to be allocated
 * Flow Variant: 68 Data flow: data passed as a global variable from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#ifndef _WIN32
#include <wchar.h>
#endif

#define HELLO_STRING "hello"

namespace CWE789_Uncontrolled_Mem_Alloc__new_char_fscanf_68
{

size_t badData;
size_t goodG2BData;
size_t goodB2GData;

#ifndef OMITBAD

/* bad function declaration */
void badSink();

void bad()
{
    size_t data;
    /* Initialize data */
    data = 0;
    /* POTENTIAL FLAW: Read data from the console using fscanf() */
    fscanf(stdin, "%ud", &data);
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
    size_t data;
    /* Initialize data */
    data = 0;
    /* FIX: Use a relatively small number for memory allocation */
    data = 20;
    goodG2BData = data;
    goodG2BSink();
}

/* goodB2G uses the BadSource with the GoodSink */
static void goodB2G()
{
    size_t data;
    /* Initialize data */
    data = 0;
    /* POTENTIAL FLAW: Read data from the console using fscanf() */
    fscanf(stdin, "%ud", &data);
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

using namespace CWE789_Uncontrolled_Mem_Alloc__new_char_fscanf_68; /* so that we can use good and bad easily */

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
