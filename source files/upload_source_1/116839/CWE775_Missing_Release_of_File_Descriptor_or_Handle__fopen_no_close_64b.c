/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE775_Missing_Release_of_File_Descriptor_or_Handle__fopen_no_close_64b.c
Label Definition File: CWE775_Missing_Release_of_File_Descriptor_or_Handle__fopen_no_close.label.xml
Template File: source-sinks-64b.tmpl.c
*/
/*
 * @description
 * CWE: 775 Missing Release of File Descriptor or Handle After Effective Lifetime
 * BadSource:  Open a file using fopen()
 * Sinks:
 *    GoodSink: Close the file using fclose()
 *    BadSink : Do not close file
 * Flow Variant: 64 Data flow: void pointer to data passed from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#ifndef OMITBAD

void CWE775_Missing_Release_of_File_Descriptor_or_Handle__fopen_no_close_64b_badSink(void * dataVoidPtr)
{
    /* cast void pointer to a pointer of the appropriate type */
    FILE * * dataPtr = (FILE * *)dataVoidPtr;
    /* dereference dataPtr into data */
    FILE * data = (*dataPtr);
    /* FLAW: No attempt to close the file */
    ; /* empty statement needed for some flow variants */
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G uses the BadSource with the GoodSink */
void CWE775_Missing_Release_of_File_Descriptor_or_Handle__fopen_no_close_64b_goodB2GSink(void * dataVoidPtr)
{
    /* cast void pointer to a pointer of the appropriate type */
    FILE * * dataPtr = (FILE * *)dataVoidPtr;
    /* dereference dataPtr into data */
    FILE * data = (*dataPtr);
    /* FIX: If the file is still opened, close it */
    if (data != NULL)
    {
        fclose(data);
    }
}

#endif /* OMITGOOD */
