/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE36_Absolute_Path_Traversal__char_file_ofstream_81.h
Label Definition File: CWE36_Absolute_Path_Traversal.label.xml
Template File: sources-sink-81.tmpl.h
*/
/*
 * @description
 * CWE: 36 Absolute Path Traversal
 * BadSource: file Read input from a file
 * GoodSource: Full path and file name
 * Sinks: ofstream
 *    BadSink : Open the file named in data using ofstream::open()
 * Flow Variant: 81 Data flow: data passed in a parameter to a virtual method called via a reference
 *
 * */

#include "std_testcase.h"

#ifndef _WIN32
#include <wchar.h>
#endif

namespace CWE36_Absolute_Path_Traversal__char_file_ofstream_81
{

class CWE36_Absolute_Path_Traversal__char_file_ofstream_81_base
{
public:
    /* pure virtual function */
    virtual void action(char * data) const = 0;
};

#ifndef OMITBAD

class CWE36_Absolute_Path_Traversal__char_file_ofstream_81_bad : public CWE36_Absolute_Path_Traversal__char_file_ofstream_81_base
{
public:
    void action(char * data) const;
};

#endif /* OMITBAD */

#ifndef OMITGOOD

class CWE36_Absolute_Path_Traversal__char_file_ofstream_81_goodG2B : public CWE36_Absolute_Path_Traversal__char_file_ofstream_81_base
{
public:
    void action(char * data) const;
};

#endif /* OMITGOOD */

}
