/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE126_Buffer_Overread__char_declare_memmove_67a.c
Label Definition File: CWE126_Buffer_Overread.stack.label.xml
Template File: sources-sink-67a.tmpl.c
*/
/*
 * @description
 * CWE: 126 Buffer Over-read
 * BadSource:  Set data pointer to a small buffer
 * GoodSource: Set data pointer to a large buffer
 * Sinks: memmove
 *    BadSink : Copy data to string using memmove
 * Flow Variant: 67 Data flow: data passed in a struct from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

typedef struct _CWE126_Buffer_Overread__char_declare_memmove_67_structType
{
    char * structFirst;
} CWE126_Buffer_Overread__char_declare_memmove_67_structType;

#ifndef OMITBAD

/* bad function declaration */
void CWE126_Buffer_Overread__char_declare_memmove_67b_badSink(CWE126_Buffer_Overread__char_declare_memmove_67_structType myStruct);

void CWE126_Buffer_Overread__char_declare_memmove_67_bad()
{
    char * data;
    CWE126_Buffer_Overread__char_declare_memmove_67_structType myStruct;
    char dataBadBuffer[50];
    char dataGoodBuffer[100];
    memset(dataBadBuffer, 'A', 50-1); /* fill with 'A's */
    dataBadBuffer[50-1] = '\0'; /* null terminate */
    memset(dataGoodBuffer, 'A', 100-1); /* fill with 'A's */
    dataGoodBuffer[100-1] = '\0'; /* null terminate */
    /* FLAW: Set data pointer to a small buffer */
    data = dataBadBuffer;
    myStruct.structFirst = data;
    CWE126_Buffer_Overread__char_declare_memmove_67b_badSink(myStruct);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE126_Buffer_Overread__char_declare_memmove_67b_goodG2BSink(CWE126_Buffer_Overread__char_declare_memmove_67_structType myStruct);

static void goodG2B()
{
    char * data;
    CWE126_Buffer_Overread__char_declare_memmove_67_structType myStruct;
    char dataBadBuffer[50];
    char dataGoodBuffer[100];
    memset(dataBadBuffer, 'A', 50-1); /* fill with 'A's */
    dataBadBuffer[50-1] = '\0'; /* null terminate */
    memset(dataGoodBuffer, 'A', 100-1); /* fill with 'A's */
    dataGoodBuffer[100-1] = '\0'; /* null terminate */
    /* FIX: Set data pointer to a large buffer */
    data = dataGoodBuffer;
    myStruct.structFirst = data;
    CWE126_Buffer_Overread__char_declare_memmove_67b_goodG2BSink(myStruct);
}

void CWE126_Buffer_Overread__char_declare_memmove_67_good()
{
    goodG2B();
}

#endif /* OMITGOOD */

/* Below is the main(). It is only used when building this testcase on
 * its own for testing or for building a binary to use in testing binary
 * analysis tools. It is not used when compiling all the testcases as one
 * application, which is how source code analysis tools are tested.
 */

#ifdef INCLUDEMAIN

int main(int argc, char * argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
    printLine("Calling good()...");
    CWE126_Buffer_Overread__char_declare_memmove_67_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE126_Buffer_Overread__char_declare_memmove_67_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
