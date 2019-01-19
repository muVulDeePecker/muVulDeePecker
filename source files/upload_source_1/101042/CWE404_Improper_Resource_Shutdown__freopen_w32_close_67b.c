/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE404_Improper_Resource_Shutdown__freopen_w32_close_67b.c
Label Definition File: CWE404_Improper_Resource_Shutdown.label.xml
Template File: source-sinks-67b.tmpl.c
*/
/*
 * @description
 * CWE: 404 Improper Resource Shutdown or Release
 * BadSource: freopen Open a file using freopen()
 * Sinks: w32_close
 *    GoodSink: Close the file using fclose()
 *    BadSink : Close the file using close()
 * Flow Variant: 67 Data flow: data passed in a struct from one function to another in different source files
 *
 * */

#include "std_testcase.h"

typedef struct _CWE404_Improper_Resource_Shutdown__freopen_w32_close_67_structType
{
    FILE * structFirst;
} CWE404_Improper_Resource_Shutdown__freopen_w32_close_67_structType;

#ifndef OMITBAD

void CWE404_Improper_Resource_Shutdown__freopen_w32_close_67b_badSink(CWE404_Improper_Resource_Shutdown__freopen_w32_close_67_structType myStruct)
{
    FILE * data = myStruct.structFirst;
    if (data != NULL)
    {
        /* FLAW: Attempt to close the file using close() instead of fclose() */
        _close((int)data);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G uses the BadSource with the GoodSink */
void CWE404_Improper_Resource_Shutdown__freopen_w32_close_67b_goodB2GSink(CWE404_Improper_Resource_Shutdown__freopen_w32_close_67_structType myStruct)
{
    FILE * data = myStruct.structFirst;
    if (data != NULL)
    {
        /* FIX: Close the file using fclose() */
        fclose(data);
    }
}

#endif /* OMITGOOD */
