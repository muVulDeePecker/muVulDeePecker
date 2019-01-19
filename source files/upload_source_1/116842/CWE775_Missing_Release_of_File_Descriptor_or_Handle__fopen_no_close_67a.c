/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE775_Missing_Release_of_File_Descriptor_or_Handle__fopen_no_close_67a.c
Label Definition File: CWE775_Missing_Release_of_File_Descriptor_or_Handle__fopen_no_close.label.xml
Template File: source-sinks-67a.tmpl.c
*/
/*
 * @description
 * CWE: 775 Missing Release of File Descriptor or Handle After Effective Lifetime
 * BadSource:  Open a file using fopen()
 * Sinks:
 *    GoodSink: Close the file using fclose()
 *    BadSink : Do not close file
 * Flow Variant: 67 Data flow: data passed in a struct from one function to another in different source files
 *
 * */

#include "std_testcase.h"

typedef struct _CWE775_Missing_Release_of_File_Descriptor_or_Handle__fopen_no_close_67_structType
{
    FILE * structFirst;
} CWE775_Missing_Release_of_File_Descriptor_or_Handle__fopen_no_close_67_structType;

#ifndef OMITBAD

/* bad function declaration */
void CWE775_Missing_Release_of_File_Descriptor_or_Handle__fopen_no_close_67b_badSink(CWE775_Missing_Release_of_File_Descriptor_or_Handle__fopen_no_close_67_structType myStruct);

void CWE775_Missing_Release_of_File_Descriptor_or_Handle__fopen_no_close_67_bad()
{
    FILE * data;
    CWE775_Missing_Release_of_File_Descriptor_or_Handle__fopen_no_close_67_structType myStruct;
    data = NULL;
    /* POTENTIAL FLAW: Open a file without closing it */
    data = fopen("BadSource_fopen.txt", "w+");
    myStruct.structFirst = data;
    CWE775_Missing_Release_of_File_Descriptor_or_Handle__fopen_no_close_67b_badSink(myStruct);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G uses the BadSource with the GoodSink */
void CWE775_Missing_Release_of_File_Descriptor_or_Handle__fopen_no_close_67b_goodB2GSink(CWE775_Missing_Release_of_File_Descriptor_or_Handle__fopen_no_close_67_structType myStruct);

static void goodB2G()
{
    FILE * data;
    CWE775_Missing_Release_of_File_Descriptor_or_Handle__fopen_no_close_67_structType myStruct;
    data = NULL;
    /* POTENTIAL FLAW: Open a file without closing it */
    data = fopen("BadSource_fopen.txt", "w+");
    myStruct.structFirst = data;
    CWE775_Missing_Release_of_File_Descriptor_or_Handle__fopen_no_close_67b_goodB2GSink(myStruct);
}

void CWE775_Missing_Release_of_File_Descriptor_or_Handle__fopen_no_close_67_good()
{
    goodB2G();
}

#endif /* OMITGOOD */

/* Below is the main(). It is only used when building this testcase on
   its own for testing or for building a binary to use in testing binary
   analysis tools. It is not used when compiling all the testcases as one
   application, which is how source code analysis tools are tested. */

#ifdef INCLUDEMAIN

int main(int argc, char * argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
    printLine("Calling good()...");
    CWE775_Missing_Release_of_File_Descriptor_or_Handle__fopen_no_close_67_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE775_Missing_Release_of_File_Descriptor_or_Handle__fopen_no_close_67_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
