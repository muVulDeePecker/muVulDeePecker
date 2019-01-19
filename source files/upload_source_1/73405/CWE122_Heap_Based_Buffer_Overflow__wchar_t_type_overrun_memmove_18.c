/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__wchar_t_type_overrun_memmove_18.c
Label Definition File: CWE122_Heap_Based_Buffer_Overflow.label.xml
Template File: point-flaw-18.tmpl.c
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * Sinks: type_overrun_memmove
 *    GoodSink: Perform the memmove() and prevent overwriting part of the structure
 *    BadSink : Overwrite part of the structure by incorrectly using the sizeof(struct) in memmove()
 * Flow Variant: 18 Control flow: goto statements
 *
 * */

#include "std_testcase.h"

#ifndef _WIN32
#include <wchar.h>
#endif

#define SRC_STR L"0123456789abcde0123"

typedef struct _charVoid
{
    wchar_t charFirst[16];
    void * voidSecond;
    void * voidThird;
} charVoid;

#ifndef OMITBAD

void CWE122_Heap_Based_Buffer_Overflow__wchar_t_type_overrun_memmove_18_bad()
{
    goto sink;
sink:
    {
        charVoid * structCharVoid = (charVoid *)malloc(sizeof(charVoid));
        structCharVoid->voidSecond = (void *)SRC_STR;
        /* Print the initial block pointed to by structCharVoid->voidSecond */
        printWLine((wchar_t *)structCharVoid->voidSecond);
        /* FLAW: Use the sizeof(*structCharVoid) which will overwrite the pointer y */
        memmove(structCharVoid->charFirst, SRC_STR, sizeof(*structCharVoid));
        structCharVoid->charFirst[(sizeof(structCharVoid->charFirst)/sizeof(wchar_t))-1] = L'\0'; /* null terminate the string */
        printWLine((wchar_t *)structCharVoid->charFirst);
        printWLine((wchar_t *)structCharVoid->voidSecond);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good1() reverses the blocks on the goto statement */
static void good1()
{
    goto sink;
sink:
    {
        charVoid * structCharVoid = (charVoid *)malloc(sizeof(charVoid));
        structCharVoid->voidSecond = (void *)SRC_STR;
        /* Print the initial block pointed to by structCharVoid->voidSecond */
        printWLine((wchar_t *)structCharVoid->voidSecond);
        /* FIX: Use the sizeof(structCharVoid->charFirst) to avoid overwriting the pointer y */
        memmove(structCharVoid->charFirst, SRC_STR, sizeof(structCharVoid->charFirst));
        structCharVoid->charFirst[(sizeof(structCharVoid->charFirst)/sizeof(wchar_t))-1] = L'\0'; /* null terminate the string */
        printWLine((wchar_t *)structCharVoid->charFirst);
        printWLine((wchar_t *)structCharVoid->voidSecond);
    }
}

void CWE122_Heap_Based_Buffer_Overflow__wchar_t_type_overrun_memmove_18_good()
{
    good1();
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
    CWE122_Heap_Based_Buffer_Overflow__wchar_t_type_overrun_memmove_18_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE122_Heap_Based_Buffer_Overflow__wchar_t_type_overrun_memmove_18_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
