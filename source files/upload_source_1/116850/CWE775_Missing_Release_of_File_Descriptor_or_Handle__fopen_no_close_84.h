/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE775_Missing_Release_of_File_Descriptor_or_Handle__fopen_no_close_84.h
Label Definition File: CWE775_Missing_Release_of_File_Descriptor_or_Handle__fopen_no_close.label.xml
Template File: source-sinks-84.tmpl.h
*/
/*
 * @description
 * CWE: 775 Missing Release of File Descriptor or Handle After Effective Lifetime
 * BadSource:  Open a file using fopen()
 * Sinks:
 *    GoodSink: Close the file using fclose()
 *    BadSink : Do not close file
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */

#include "std_testcase.h"

namespace CWE775_Missing_Release_of_File_Descriptor_or_Handle__fopen_no_close_84
{

#ifndef OMITBAD

class CWE775_Missing_Release_of_File_Descriptor_or_Handle__fopen_no_close_84_bad
{
public:
    CWE775_Missing_Release_of_File_Descriptor_or_Handle__fopen_no_close_84_bad(FILE * dataCopy);
    ~CWE775_Missing_Release_of_File_Descriptor_or_Handle__fopen_no_close_84_bad();

private:
    FILE * data;
};

#endif /* OMITBAD */

#ifndef OMITGOOD

class CWE775_Missing_Release_of_File_Descriptor_or_Handle__fopen_no_close_84_goodB2G
{
public:
    CWE775_Missing_Release_of_File_Descriptor_or_Handle__fopen_no_close_84_goodB2G(FILE * dataCopy);
    ~CWE775_Missing_Release_of_File_Descriptor_or_Handle__fopen_no_close_84_goodB2G();

private:
    FILE * data;
};

#endif /* OMITGOOD */

}
