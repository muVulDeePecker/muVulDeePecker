/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__CWE135_66a.c
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__CWE135.label.xml
Template File: sources-sinks-66a.tmpl.c
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Void pointer to a wchar_t array
 * GoodSource: Void pointer to a char array
 * Sinks:
 *    GoodSink: Allocate memory using wcslen() and copy data
 *    BadSink : Allocate memory using strlen() and copy data
 * Flow Variant: 66 Data flow: data passed in an array from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

/* bad function declaration */
void CWE122_Heap_Based_Buffer_Overflow__CWE135_66b_badSink(void * dataArray[]);

void CWE122_Heap_Based_Buffer_Overflow__CWE135_66_bad()
{
    void * data;
    void * dataArray[5];
    data = NULL;
    {
        wchar_t * dataBadBuffer = (wchar_t *)malloc(50*sizeof(wchar_t));
        wmemset(dataBadBuffer, L'A', 50-1);
        dataBadBuffer[50-1] = L'\0';
        /* POTENTIAL FLAW: Set data to point to a wide string */
        data = (void *)dataBadBuffer;
    }
    /* put data in array */
    dataArray[2] = data;
    CWE122_Heap_Based_Buffer_Overflow__CWE135_66b_badSink(dataArray);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE122_Heap_Based_Buffer_Overflow__CWE135_66b_goodG2BSink(void * dataArray[]);

static void goodG2B()
{
    void * data;
    void * dataArray[5];
    data = NULL;
    {
        char * dataGoodBuffer = (char *)malloc(50*sizeof(char));
        memset(dataGoodBuffer, 'A', 50-1);
        dataGoodBuffer[50-1] = '\0';
        /* FIX: Set data to point to a char string */
        data = (void *)dataGoodBuffer;
    }
    dataArray[2] = data;
    CWE122_Heap_Based_Buffer_Overflow__CWE135_66b_goodG2BSink(dataArray);
}

/* goodB2G uses the BadSource with the GoodSink */
void CWE122_Heap_Based_Buffer_Overflow__CWE135_66b_goodB2GSink(void * dataArray[]);

static void goodB2G()
{
    void * data;
    void * dataArray[5];
    data = NULL;
    {
        wchar_t * dataBadBuffer = (wchar_t *)malloc(50*sizeof(wchar_t));
        wmemset(dataBadBuffer, L'A', 50-1);
        dataBadBuffer[50-1] = L'\0';
        /* POTENTIAL FLAW: Set data to point to a wide string */
        data = (void *)dataBadBuffer;
    }
    dataArray[2] = data;
    CWE122_Heap_Based_Buffer_Overflow__CWE135_66b_goodB2GSink(dataArray);
}

void CWE122_Heap_Based_Buffer_Overflow__CWE135_66_good()
{
    goodG2B();
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
    CWE122_Heap_Based_Buffer_Overflow__CWE135_66_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE122_Heap_Based_Buffer_Overflow__CWE135_66_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
