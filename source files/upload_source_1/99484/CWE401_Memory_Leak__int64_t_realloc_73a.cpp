/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE401_Memory_Leak__int64_t_realloc_73a.cpp
Label Definition File: CWE401_Memory_Leak.c.label.xml
Template File: sources-sinks-73a.tmpl.cpp
*/
/*
 * @description
 * CWE: 401 Memory Leak
 * BadSource: realloc Allocate data using realloc()
 * GoodSource: Allocate data on the stack
 * Sinks:
 *    GoodSink: call free() on data
 *    BadSink : no deallocation of data
 * Flow Variant: 73 Data flow: data passed in a list from one function to another in different source files
 *
 * */

#include "std_testcase.h"
#include <list>

#include <wchar.h>

using namespace std;

namespace CWE401_Memory_Leak__int64_t_realloc_73
{

#ifndef OMITBAD

/* bad function declaration */
void badSink(list<int64_t *> dataList);

void bad()
{
    int64_t * data;
    list<int64_t *> dataList;
    data = NULL;
    /* POTENTIAL FLAW: Allocate memory on the heap */
    data = (int64_t *)realloc(data, 100*sizeof(int64_t));
    /* Initialize and make use of data */
    data[0] = 5LL;
    printLongLongLine(data[0]);
    /* Put data in a list */
    dataList.push_back(data);
    dataList.push_back(data);
    dataList.push_back(data);
    badSink(dataList);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void goodG2BSink(list<int64_t *> dataList);

static void goodG2B()
{
    int64_t * data;
    list<int64_t *> dataList;
    data = NULL;
    /* FIX: Use memory allocated on the stack with ALLOCA */
    data = (int64_t *)ALLOCA(100*sizeof(int64_t));
    /* Initialize and make use of data */
    data[0] = 5LL;
    printLongLongLine(data[0]);
    /* Put data in a list */
    dataList.push_back(data);
    dataList.push_back(data);
    dataList.push_back(data);
    goodG2BSink(dataList);
}

/* goodB2G uses the BadSource with the GoodSink */
void goodB2GSink(list<int64_t *> dataList);

static void goodB2G()
{
    int64_t * data;
    list<int64_t *> dataList;
    data = NULL;
    /* POTENTIAL FLAW: Allocate memory on the heap */
    data = (int64_t *)realloc(data, 100*sizeof(int64_t));
    /* Initialize and make use of data */
    data[0] = 5LL;
    printLongLongLine(data[0]);
    dataList.push_back(data);
    dataList.push_back(data);
    dataList.push_back(data);
    goodB2GSink(dataList);
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

using namespace CWE401_Memory_Leak__int64_t_realloc_73; /* so that we can use good and bad easily */

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
