/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_07.c
Label Definition File: CWE122_Heap_Based_Buffer_Overflow.label.xml
Template File: point-flaw-07.tmpl.c
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * Sinks: type_overrun_memcpy
 *    GoodSink: Perform the memcpy() and prevent overwriting part of the structure
 *    BadSink : Overwrite part of the structure by incorrectly using the sizeof(struct) in memcpy()
 * Flow Variant: 07 Control flow: if(staticFive==5) and if(staticFive!=5)
 *
 * */

#include "std_testcase.h"

#ifndef _WIN32
#include <wchar.h>
#endif

#define SRC_STR "0123456789abcde0123"

typedef struct _charVoid
{
    char charFirst[16];
    void * voidSecond;
    void * voidThird;
} charVoid;

/* The variable below is not declared "const", but is never assigned
   any other value so a tool should be able to identify that reads of
   this will always give its initialized value. */
static int staticFive = 5;

#ifndef OMITBAD

void CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_07_bad()
{
    if(staticFive==5)
    {
        {
            charVoid * structCharVoid = (charVoid *)malloc(sizeof(charVoid));
            structCharVoid->voidSecond = (void *)SRC_STR;
            /* Print the initial block pointed to by structCharVoid->voidSecond */
            printLine((char *)structCharVoid->voidSecond);
            /* FLAW: Use the sizeof(*structCharVoid) which will overwrite the pointer y */
            memcpy(structCharVoid->charFirst, SRC_STR, sizeof(*structCharVoid));
            structCharVoid->charFirst[(sizeof(structCharVoid->charFirst)/sizeof(char))-1] = '\0'; /* null terminate the string */
            printLine((char *)structCharVoid->charFirst);
            printLine((char *)structCharVoid->voidSecond);
            free(structCharVoid);
        }
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good1() uses if(staticFive!=5) instead of if(staticFive==5) */
static void good1()
{
    if(staticFive!=5)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        {
            charVoid * structCharVoid = (charVoid *)malloc(sizeof(charVoid));
            structCharVoid->voidSecond = (void *)SRC_STR;
            /* Print the initial block pointed to by structCharVoid->voidSecond */
            printLine((char *)structCharVoid->voidSecond);
            /* FIX: Use the sizeof(structCharVoid->charFirst) to avoid overwriting the pointer y */
            memcpy(structCharVoid->charFirst, SRC_STR, sizeof(structCharVoid->charFirst));
            structCharVoid->charFirst[(sizeof(structCharVoid->charFirst)/sizeof(char))-1] = '\0'; /* null terminate the string */
            printLine((char *)structCharVoid->charFirst);
            printLine((char *)structCharVoid->voidSecond);
            free(structCharVoid);
        }
    }
}

/* good2() reverses the bodies in the if statement */
static void good2()
{
    if(staticFive==5)
    {
        {
            charVoid * structCharVoid = (charVoid *)malloc(sizeof(charVoid));
            structCharVoid->voidSecond = (void *)SRC_STR;
            /* Print the initial block pointed to by structCharVoid->voidSecond */
            printLine((char *)structCharVoid->voidSecond);
            /* FIX: Use the sizeof(structCharVoid->charFirst) to avoid overwriting the pointer y */
            memcpy(structCharVoid->charFirst, SRC_STR, sizeof(structCharVoid->charFirst));
            structCharVoid->charFirst[(sizeof(structCharVoid->charFirst)/sizeof(char))-1] = '\0'; /* null terminate the string */
            printLine((char *)structCharVoid->charFirst);
            printLine((char *)structCharVoid->voidSecond);
            free(structCharVoid);
        }
    }
}

void CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_07_good()
{
    good1();
    good2();
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
    CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_07_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_07_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
