/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE773_Missing_Reference_to_Active_File_Descriptor_or_Handle__w32CreateFile_53c.c
Label Definition File: CWE773_Missing_Reference_to_Active_File_Descriptor_or_Handle__w32CreateFile.label.xml
Template File: source-sinks-53c.tmpl.c
*/
/*
 * @description
 * CWE: 773 Missing Reference to Active File Descriptor or Handle
 * BadSource:  Create a file handle using CreateFile()
 * Sinks:
 *    GoodSink: Close the file handle before reusing it
 *    BadSink : Reassign the file handle before closing it
 * Flow Variant: 53 Data flow: data passed as an argument from one function through two others to a fourth; all four functions are in different source files
 *
 * */

#include "std_testcase.h"

#include <windows.h>

#ifndef OMITBAD

/* bad function declaration */
void CWE773_Missing_Reference_to_Active_File_Descriptor_or_Handle__w32CreateFile_53d_badSink(HANDLE data);

void CWE773_Missing_Reference_to_Active_File_Descriptor_or_Handle__w32CreateFile_53c_badSink(HANDLE data)
{
    CWE773_Missing_Reference_to_Active_File_Descriptor_or_Handle__w32CreateFile_53d_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G uses the BadSource with the GoodSink */
void CWE773_Missing_Reference_to_Active_File_Descriptor_or_Handle__w32CreateFile_53d_goodB2GSink(HANDLE data);

void CWE773_Missing_Reference_to_Active_File_Descriptor_or_Handle__w32CreateFile_53c_goodB2GSink(HANDLE data)
{
    CWE773_Missing_Reference_to_Active_File_Descriptor_or_Handle__w32CreateFile_53d_goodB2GSink(data);
}

#endif /* OMITGOOD */
