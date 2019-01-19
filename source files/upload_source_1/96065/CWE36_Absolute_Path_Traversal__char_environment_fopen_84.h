/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE36_Absolute_Path_Traversal__char_environment_fopen_84.h
Label Definition File: CWE36_Absolute_Path_Traversal.label.xml
Template File: sources-sink-84.tmpl.h
*/
/*
 * @description
 * CWE: 36 Absolute Path Traversal
 * BadSource: environment Read input from an environment variable
 * GoodSource: Full path and file name
 * Sinks: fopen
 *    BadSink : Open the file named in data using fopen()
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */

#include "std_testcase.h"

#ifndef _WIN32
#include <wchar.h>
#endif

namespace CWE36_Absolute_Path_Traversal__char_environment_fopen_84
{

#ifndef OMITBAD

class CWE36_Absolute_Path_Traversal__char_environment_fopen_84_bad
{
public:
    CWE36_Absolute_Path_Traversal__char_environment_fopen_84_bad(char * dataCopy);
    ~CWE36_Absolute_Path_Traversal__char_environment_fopen_84_bad();

private:
    char * data;
};

#endif /* OMITBAD */

#ifndef OMITGOOD

class CWE36_Absolute_Path_Traversal__char_environment_fopen_84_goodG2B
{
public:
    CWE36_Absolute_Path_Traversal__char_environment_fopen_84_goodG2B(char * dataCopy);
    ~CWE36_Absolute_Path_Traversal__char_environment_fopen_84_goodG2B();

private:
    char * data;
};

#endif /* OMITGOOD */

}
