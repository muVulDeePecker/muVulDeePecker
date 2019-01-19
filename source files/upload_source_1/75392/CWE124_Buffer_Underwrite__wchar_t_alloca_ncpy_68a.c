/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE124_Buffer_Underwrite__wchar_t_alloca_ncpy_68a.c
Label Definition File: CWE124_Buffer_Underwrite.stack.label.xml
Template File: sources-sink-68a.tmpl.c
*/
/*
 * @description
 * CWE: 124 Buffer Underwrite
 * BadSource:  Set data pointer to before the allocated memory buffer
 * GoodSource: Set data pointer to the allocated memory buffer
 * Sink: ncpy
 *    BadSink : Copy string to data using wcsncpy
 * Flow Variant: 68 Data flow: data passed as a global variable from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

wchar_t * CWE124_Buffer_Underwrite__wchar_t_alloca_ncpy_68_badData;
wchar_t * CWE124_Buffer_Underwrite__wchar_t_alloca_ncpy_68_goodG2BData;

#ifndef OMITBAD

/* bad function declaration */
void CWE124_Buffer_Underwrite__wchar_t_alloca_ncpy_68b_badSink();

void CWE124_Buffer_Underwrite__wchar_t_alloca_ncpy_68_bad()
{
    wchar_t * data;
    wchar_t * dataBuffer = (wchar_t *)ALLOCA(100*sizeof(wchar_t));
    wmemset(dataBuffer, L'A', 100-1);
    dataBuffer[100-1] = L'\0';
    /* FLAW: Set data pointer to before the allocated memory buffer */
    data = dataBuffer - 8;
    CWE124_Buffer_Underwrite__wchar_t_alloca_ncpy_68_badData = data;
    CWE124_Buffer_Underwrite__wchar_t_alloca_ncpy_68b_badSink();
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good function declarations */
void CWE124_Buffer_Underwrite__wchar_t_alloca_ncpy_68b_goodG2BSink();

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B()
{
    wchar_t * data;
    wchar_t * dataBuffer = (wchar_t *)ALLOCA(100*sizeof(wchar_t));
    wmemset(dataBuffer, L'A', 100-1);
    dataBuffer[100-1] = L'\0';
    /* FIX: Set data pointer to the allocated memory buffer */
    data = dataBuffer;
    CWE124_Buffer_Underwrite__wchar_t_alloca_ncpy_68_goodG2BData = data;
    CWE124_Buffer_Underwrite__wchar_t_alloca_ncpy_68b_goodG2BSink();
}

void CWE124_Buffer_Underwrite__wchar_t_alloca_ncpy_68_good()
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
    CWE124_Buffer_Underwrite__wchar_t_alloca_ncpy_68_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE124_Buffer_Underwrite__wchar_t_alloca_ncpy_68_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
