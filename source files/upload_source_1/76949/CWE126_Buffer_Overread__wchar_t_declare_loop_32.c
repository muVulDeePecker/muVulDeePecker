/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE126_Buffer_Overread__wchar_t_declare_loop_32.c
Label Definition File: CWE126_Buffer_Overread.stack.label.xml
Template File: sources-sink-32.tmpl.c
*/
/*
 * @description
 * CWE: 126 Buffer Over-read
 * BadSource:  Set data pointer to a small buffer
 * GoodSource: Set data pointer to a large buffer
 * Sink: loop
 *    BadSink : Copy data to string using a loop
 * Flow Variant: 32 Data flow using two pointers to the same value within the same function
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

void CWE126_Buffer_Overread__wchar_t_declare_loop_32_bad()
{
    wchar_t * data;
    wchar_t * *dataPtr1 = &data;
    wchar_t * *dataPtr2 = &data;
    wchar_t dataBadBuffer[50];
    wchar_t dataGoodBuffer[100];
    wmemset(dataBadBuffer, L'A', 50-1); /* fill with 'A's */
    dataBadBuffer[50-1] = L'\0'; /* null terminate */
    wmemset(dataGoodBuffer, L'A', 100-1); /* fill with 'A's */
    dataGoodBuffer[100-1] = L'\0'; /* null terminate */
    {
        wchar_t * data = *dataPtr1;
        /* FLAW: Set data pointer to a small buffer */
        data = dataBadBuffer;
        *dataPtr1 = data;
    }
    {
        wchar_t * data = *dataPtr2;
        {
            size_t i, destLen;
            wchar_t dest[100];
            wmemset(dest, L'C', 100-1);
            dest[100-1] = L'\0'; /* null terminate */
            destLen = wcslen(dest);
            /* POTENTIAL FLAW: using length of the dest where data
             * could be smaller than dest causing buffer overread */
            for (i = 0; i < destLen; i++)
            {
                dest[i] = data[i];
            }
            dest[100-1] = L'\0';
            printWLine(dest);
        }
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B() uses the GoodSource with the BadSink */
static void goodG2B()
{
    wchar_t * data;
    wchar_t * *dataPtr1 = &data;
    wchar_t * *dataPtr2 = &data;
    wchar_t dataBadBuffer[50];
    wchar_t dataGoodBuffer[100];
    wmemset(dataBadBuffer, L'A', 50-1); /* fill with 'A's */
    dataBadBuffer[50-1] = L'\0'; /* null terminate */
    wmemset(dataGoodBuffer, L'A', 100-1); /* fill with 'A's */
    dataGoodBuffer[100-1] = L'\0'; /* null terminate */
    {
        wchar_t * data = *dataPtr1;
        /* FIX: Set data pointer to a large buffer */
        data = dataGoodBuffer;
        *dataPtr1 = data;
    }
    {
        wchar_t * data = *dataPtr2;
        {
            size_t i, destLen;
            wchar_t dest[100];
            wmemset(dest, L'C', 100-1);
            dest[100-1] = L'\0'; /* null terminate */
            destLen = wcslen(dest);
            /* POTENTIAL FLAW: using length of the dest where data
             * could be smaller than dest causing buffer overread */
            for (i = 0; i < destLen; i++)
            {
                dest[i] = data[i];
            }
            dest[100-1] = L'\0';
            printWLine(dest);
        }
    }
}

void CWE126_Buffer_Overread__wchar_t_declare_loop_32_good()
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
    CWE126_Buffer_Overread__wchar_t_declare_loop_32_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE126_Buffer_Overread__wchar_t_declare_loop_32_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
