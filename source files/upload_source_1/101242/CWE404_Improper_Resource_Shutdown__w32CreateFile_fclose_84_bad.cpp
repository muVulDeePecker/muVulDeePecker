/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE404_Improper_Resource_Shutdown__w32CreateFile_fclose_84_bad.cpp
Label Definition File: CWE404_Improper_Resource_Shutdown__w32CreateFile.label.xml
Template File: source-sinks-84_bad.tmpl.cpp
*/
/*
 * @description
 * CWE: 404 Improper Resource Shutdown or Release
 * BadSource:  Open a file using CreateFile()
 * Sinks: fclose
 *    GoodSink: Close the file using CloseHandle()
 *    BadSink : Close the file using fclose()
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */
#ifndef OMITBAD

#include "std_testcase.h"
#include "CWE404_Improper_Resource_Shutdown__w32CreateFile_fclose_84.h"

namespace CWE404_Improper_Resource_Shutdown__w32CreateFile_fclose_84
{
CWE404_Improper_Resource_Shutdown__w32CreateFile_fclose_84_bad::CWE404_Improper_Resource_Shutdown__w32CreateFile_fclose_84_bad(HANDLE dataCopy)
{
    data = dataCopy;
    /* POTENTIAL FLAW: Open a file - need to make sure it is closed properly in the sink */
    data = CreateFile("BadSource_w32CreateFile.txt",
                      (GENERIC_WRITE|GENERIC_READ),
                      0,
                      NULL,
                      OPEN_ALWAYS,
                      FILE_ATTRIBUTE_NORMAL,
                      NULL);
}

CWE404_Improper_Resource_Shutdown__w32CreateFile_fclose_84_bad::~CWE404_Improper_Resource_Shutdown__w32CreateFile_fclose_84_bad()
{
    if (data != INVALID_HANDLE_VALUE)
    {
        /* FLAW: Attempt to close the file using fclose() instead of CloseHandle() */
        fclose((FILE *)data);
    }
}
}
#endif /* OMITBAD */
