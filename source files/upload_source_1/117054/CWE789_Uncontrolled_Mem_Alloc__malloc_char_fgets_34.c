/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE789_Uncontrolled_Mem_Alloc__malloc_char_fgets_34.c
Label Definition File: CWE789_Uncontrolled_Mem_Alloc__malloc.label.xml
Template File: sources-sinks-34.tmpl.c
*/
/*
 * @description
 * CWE: 789 Uncontrolled Memory Allocation
 * BadSource: fgets Read data from the console using fgets()
 * GoodSource: Small number greater than zero
 * Sinks:
 *    GoodSink: Allocate memory with malloc() and check the size of the memory to be allocated
 *    BadSink : Allocate memory with malloc(), but incorrectly check the size of the memory to be allocated
 * Flow Variant: 34 Data flow: use of a union containing two methods of accessing the same data (within the same function)
 *
 * */

#include "std_testcase.h"

#ifndef _WIN32
#include <wchar.h>
#endif

#define CHAR_ARRAY_SIZE (3 * sizeof(data) + 2)

#define HELLO_STRING "hello"

typedef union
{
    size_t unionFirst;
    size_t unionSecond;
} CWE789_Uncontrolled_Mem_Alloc__malloc_char_fgets_34_unionType;

#ifndef OMITBAD

void CWE789_Uncontrolled_Mem_Alloc__malloc_char_fgets_34_bad()
{
    size_t data;
    CWE789_Uncontrolled_Mem_Alloc__malloc_char_fgets_34_unionType myUnion;
    /* Initialize data */
    data = 0;
    {
        char inputBuffer[CHAR_ARRAY_SIZE] = "";
        /* POTENTIAL FLAW: Read data from the console using fgets() */
        if (fgets(inputBuffer, CHAR_ARRAY_SIZE, stdin) != NULL)
        {
            /* Convert to unsigned int */
            data = strtoul(inputBuffer, NULL, 0);
        }
        else
        {
            printLine("fgets() failed.");
        }
    }
    myUnion.unionFirst = data;
    {
        size_t data = myUnion.unionSecond;
        {
            char * myString;
            /* POTENTIAL FLAW: No MAXIMUM limitation for memory allocation, but ensure data is large enough
             * for the strcpy() function to not cause a buffer overflow */
            /* INCIDENTAL FLAW: The source could cause a type overrun in data or in the memory allocation */
            if (data > strlen(HELLO_STRING))
            {
                myString = (char *)malloc(data*sizeof(char));
                /* Copy a small string into myString */
                strcpy(myString, HELLO_STRING);
                printLine(myString);
                free(myString);
            }
            else
            {
                printLine("Input is less than the length of the source string");
            }
        }
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B() uses the GoodSource with the BadSink */
static void goodG2B()
{
    size_t data;
    CWE789_Uncontrolled_Mem_Alloc__malloc_char_fgets_34_unionType myUnion;
    /* Initialize data */
    data = 0;
    /* FIX: Use a relatively small number for memory allocation */
    data = 20;
    myUnion.unionFirst = data;
    {
        size_t data = myUnion.unionSecond;
        {
            char * myString;
            /* POTENTIAL FLAW: No MAXIMUM limitation for memory allocation, but ensure data is large enough
             * for the strcpy() function to not cause a buffer overflow */
            /* INCIDENTAL FLAW: The source could cause a type overrun in data or in the memory allocation */
            if (data > strlen(HELLO_STRING))
            {
                myString = (char *)malloc(data*sizeof(char));
                /* Copy a small string into myString */
                strcpy(myString, HELLO_STRING);
                printLine(myString);
                free(myString);
            }
            else
            {
                printLine("Input is less than the length of the source string");
            }
        }
    }
}

/* goodB2G() uses the BadSource with the GoodSink */
static void goodB2G()
{
    size_t data;
    CWE789_Uncontrolled_Mem_Alloc__malloc_char_fgets_34_unionType myUnion;
    /* Initialize data */
    data = 0;
    {
        char inputBuffer[CHAR_ARRAY_SIZE] = "";
        /* POTENTIAL FLAW: Read data from the console using fgets() */
        if (fgets(inputBuffer, CHAR_ARRAY_SIZE, stdin) != NULL)
        {
            /* Convert to unsigned int */
            data = strtoul(inputBuffer, NULL, 0);
        }
        else
        {
            printLine("fgets() failed.");
        }
    }
    myUnion.unionFirst = data;
    {
        size_t data = myUnion.unionSecond;
        {
            char * myString;
            /* FIX: Include a MAXIMUM limitation for memory allocation and a check to ensure data is large enough
             * for the strcpy() function to not cause a buffer overflow */
            /* INCIDENTAL FLAW: The source could cause a type overrun in data or in the memory allocation */
            if (data > strlen(HELLO_STRING) && data < 100)
            {
                myString = (char *)malloc(data*sizeof(char));
                /* Copy a small string into myString */
                strcpy(myString, HELLO_STRING);
                printLine(myString);
                free(myString);
            }
            else
            {
                printLine("Input is less than the length of the source string or too large");
            }
        }
    }
}

void CWE789_Uncontrolled_Mem_Alloc__malloc_char_fgets_34_good()
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
    CWE789_Uncontrolled_Mem_Alloc__malloc_char_fgets_34_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE789_Uncontrolled_Mem_Alloc__malloc_char_fgets_34_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
