/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE404_Improper_Resource_Shutdown__open_fclose_84_bad.cpp
Label Definition File: CWE404_Improper_Resource_Shutdown__open.label.xml
Template File: source-sinks-84_bad.tmpl.cpp
*/
/*
 * @description
 * CWE: 404 Improper Resource Shutdown or Release
 * BadSource:  Open a file using open()
 * Sinks: fclose
 *    GoodSink: Close the file using close()
 *    BadSink : Close the file using fclose()
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */
#ifndef OMITBAD

#include "std_testcase.h"
#include "CWE404_Improper_Resource_Shutdown__open_fclose_84.h"

namespace CWE404_Improper_Resource_Shutdown__open_fclose_84
{
CWE404_Improper_Resource_Shutdown__open_fclose_84_bad::CWE404_Improper_Resource_Shutdown__open_fclose_84_bad(int dataCopy)
{
    data = dataCopy;
    /* POTENTIAL FLAW: Open a file - need to make sure it is closed properly in the sink */
    data = OPEN("BadSource_open.txt", O_RDWR|O_CREAT, S_IREAD|S_IWRITE);
}

CWE404_Improper_Resource_Shutdown__open_fclose_84_bad::~CWE404_Improper_Resource_Shutdown__open_fclose_84_bad()
{
    if (data != -1)
    {
        /* FLAW: Attempt to close the file using fclose() instead of close() */
        fclose((FILE *)data);
    }
}
}
#endif /* OMITBAD */
