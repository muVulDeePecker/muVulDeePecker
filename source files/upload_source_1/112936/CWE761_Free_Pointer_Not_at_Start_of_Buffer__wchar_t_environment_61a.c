/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_61a.c
Label Definition File: CWE761_Free_Pointer_Not_at_Start_of_Buffer.label.xml
Template File: source-sinks-61a.tmpl.c
*/
/*
 * @description
 * CWE: 761 Free Pointer not at Start of Buffer
 * BadSource: environment Read input from an environment variable
 * Sinks:
 *    GoodSink: free() memory correctly at the start of the buffer
 *    BadSink : free() memory not at the start of the buffer
 * Flow Variant: 61 Data flow: data returned from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#define ENV_VARIABLE L"ADD"

#ifdef _WIN32
#define GETENV _wgetenv
#else
#define GETENV getenv
#endif

#define SEARCH_CHAR L'S'

#ifndef OMITBAD

/* bad function declaration */
wchar_t * CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_61b_badSource(wchar_t * data);

void CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_61_bad()
{
    wchar_t * data;
    data = (wchar_t *)malloc(100*sizeof(wchar_t));
    data[0] = L'\0';
    data = CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_61b_badSource(data);
    /* FLAW: We are incrementing the pointer in the loop - this will cause us to free the
     * memory block not at the start of the buffer */
    for (; *data != L'\0'; data++)
    {
        if (*data == SEARCH_CHAR)
        {
            printLine("We have a match!");
            break;
        }
    }
    free(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G uses the BadSource with the GoodSink */
wchar_t * CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_61b_goodB2GSource(wchar_t * data);

static void goodB2G()
{
    wchar_t * data;
    data = (wchar_t *)malloc(100*sizeof(wchar_t));
    data[0] = L'\0';
    data = CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_61b_goodB2GSource(data);
    {
        size_t i;
        /* FIX: Use a loop variable to traverse through the string pointed to by data */
        for (i=0; i < wcslen(data); i++)
        {
            if (data[i] == SEARCH_CHAR)
            {
                printLine("We have a match!");
                break;
            }
        }
        free(data);
    }
}

void CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_61_good()
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
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_61_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_61_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
