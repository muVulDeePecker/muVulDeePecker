/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE36_Absolute_Path_Traversal__wchar_t_connect_socket_ofstream_84_goodG2B.cpp
Label Definition File: CWE36_Absolute_Path_Traversal.label.xml
Template File: sources-sink-84_goodG2B.tmpl.cpp
*/
/*
 * @description
 * CWE: 36 Absolute Path Traversal
 * BadSource: connect_socket Read data using a connect socket (client side)
 * GoodSource: Full path and file name
 * Sinks: ofstream
 *    BadSink : Open the file named in data using ofstream::open()
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */
#ifndef OMITGOOD

#include "std_testcase.h"
#include "CWE36_Absolute_Path_Traversal__wchar_t_connect_socket_ofstream_84.h"

#include <fstream>
using namespace std;

namespace CWE36_Absolute_Path_Traversal__wchar_t_connect_socket_ofstream_84
{
CWE36_Absolute_Path_Traversal__wchar_t_connect_socket_ofstream_84_goodG2B::CWE36_Absolute_Path_Traversal__wchar_t_connect_socket_ofstream_84_goodG2B(wchar_t * dataCopy)
{
    data = dataCopy;
#ifdef _WIN32
    /* FIX: Use a fixed, full path and file name */
    wcscat(data, L"c:\\temp\\file.txt");
#else
    /* FIX: Use a fixed, full path and file name */
    wcscat(data, L"/tmp/file.txt");
#endif
}

CWE36_Absolute_Path_Traversal__wchar_t_connect_socket_ofstream_84_goodG2B::~CWE36_Absolute_Path_Traversal__wchar_t_connect_socket_ofstream_84_goodG2B()
{
    {
        ofstream outputFile;
        /* POTENTIAL FLAW: Possibly opening a file without validating the file name or path */
        outputFile.open((char *)data);
        outputFile.close();
    }
}
}
#endif /* OMITGOOD */
