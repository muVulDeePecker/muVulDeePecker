/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE464_Addition_of_Data_Structure_Sentinel__basic_05.c
Label Definition File: CWE464_Addition_of_Data_Structure_Sentinel__basic.label.xml
Template File: sources-sink-05.tmpl.c
*/
/*
 * @description
 * CWE: 464 Addition of Data Structure Sentinel
 * BadSource:  Read in data from the console and convert to an int
 * GoodSource: Set data to a fixed char
 * Sink:
 *    BadSink : Place data into and print an array
 * Flow Variant: 05 Control flow: if(staticTrue) and if(staticFalse)
 *
 * */

#include "std_testcase.h"

/* The two variables below are not defined as "const", but are never
 * assigned any other value, so a tool should be able to identify that
 * reads of these will always return their initialized values.
 */
static int staticTrue = 1; /* true */
static int staticFalse = 0; /* false */

#ifndef OMITBAD

void CWE464_Addition_of_Data_Structure_Sentinel__basic_05_bad()
{
    char data;
    data = ' ';
    if(staticTrue)
    {
        {
            char charArraySource[2];
            charArraySource[0] = (char)getc(stdin);
            charArraySource[1] = '\0';
            /* FLAW: If the character entered on the command line is not an int,
             * a null value will be returned */
            data = (char)atoi(charArraySource);
        }
    }
    {
        char charArraySink[4];
        charArraySink[0] = 'x';
        /* POTENTIAL FLAW: If data is null, the rest of the array will not be printed */
        charArraySink[1] = data;
        charArraySink[2] = 'z';
        charArraySink[3] = '\0';
        printLine(charArraySink);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B1() - use goodsource and badsink by changing the staticTrue to staticFalse */
static void goodG2B1()
{
    char data;
    data = ' ';
    if(staticFalse)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        /* FIX: Set data to be a char */
        data = 'a';
    }
    {
        char charArraySink[4];
        charArraySink[0] = 'x';
        /* POTENTIAL FLAW: If data is null, the rest of the array will not be printed */
        charArraySink[1] = data;
        charArraySink[2] = 'z';
        charArraySink[3] = '\0';
        printLine(charArraySink);
    }
}

/* goodG2B2() - use goodsource and badsink by reversing the blocks in the if statement */
static void goodG2B2()
{
    char data;
    data = ' ';
    if(staticTrue)
    {
        /* FIX: Set data to be a char */
        data = 'a';
    }
    {
        char charArraySink[4];
        charArraySink[0] = 'x';
        /* POTENTIAL FLAW: If data is null, the rest of the array will not be printed */
        charArraySink[1] = data;
        charArraySink[2] = 'z';
        charArraySink[3] = '\0';
        printLine(charArraySink);
    }
}

void CWE464_Addition_of_Data_Structure_Sentinel__basic_05_good()
{
    goodG2B1();
    goodG2B2();
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
    CWE464_Addition_of_Data_Structure_Sentinel__basic_05_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE464_Addition_of_Data_Structure_Sentinel__basic_05_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
