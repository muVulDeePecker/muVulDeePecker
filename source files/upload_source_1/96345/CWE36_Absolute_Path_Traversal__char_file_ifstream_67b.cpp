/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE36_Absolute_Path_Traversal__char_file_ifstream_67b.cpp
Label Definition File: CWE36_Absolute_Path_Traversal.label.xml
Template File: sources-sink-67b.tmpl.cpp
*/
/*
 * @description
 * CWE: 36 Absolute Path Traversal
 * BadSource: file Read input from a file
 * GoodSource: Full path and file name
 * Sinks: ifstream
 *    BadSink : Open the file named in data using ifstream::open()
 * Flow Variant: 67 Data flow: data passed in a struct from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#ifndef _WIN32
#include <wchar.h>
#endif

#ifdef _WIN32
#define FILENAME "C:\\temp\\file.txt"
#else
#define FILENAME "/tmp/file.txt"
#endif

#include <fstream>
using namespace std;

namespace CWE36_Absolute_Path_Traversal__char_file_ifstream_67
{

typedef struct _structType
{
    char * structFirst;
} structType;

#ifndef OMITBAD

void badSink(structType myStruct)
{
    char * data = myStruct.structFirst;
    {
        ifstream inputFile;
        /* POTENTIAL FLAW: Possibly opening a file without validating the file name or path */
        inputFile.open((char *)data);
        inputFile.close();
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void goodG2BSink(structType myStruct)
{
    char * data = myStruct.structFirst;
    {
        ifstream inputFile;
        /* POTENTIAL FLAW: Possibly opening a file without validating the file name or path */
        inputFile.open((char *)data);
        inputFile.close();
    }
}

#endif /* OMITGOOD */

} /* close namespace */
