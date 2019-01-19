/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE90_LDAP_Injection__w32_char_file_22b.c
Label Definition File: CWE90_LDAP_Injection__w32.label.xml
Template File: sources-sink-22b.tmpl.c
*/
/*
 * @description
 * CWE: 90 LDAP Injection
 * BadSource: file Read input from a file
 * GoodSource: Use a fixed string
 * Sink:
 *    BadSink : data concatenated into LDAP search, which could result in LDAP Injection
 * Flow Variant: 22 Control flow: Flow controlled by value of a global variable. Sink functions are in a separate file from sources.
 *
 * */

#include "std_testcase.h"

#ifdef _WIN32
#define FILENAME "C:\\temp\\file.txt"
#else
#define FILENAME "/tmp/file.txt"
#endif

#ifndef OMITBAD

/* The global variable below is used to drive control flow in the source function */
extern int CWE90_LDAP_Injection__w32_char_file_22_badGlobal;

char * CWE90_LDAP_Injection__w32_char_file_22_badSource(char * data)
{
    if(CWE90_LDAP_Injection__w32_char_file_22_badGlobal)
    {
        {
            /* Read input from a file */
            size_t dataLen = strlen(data);
            FILE * pFile;
            /* if there is room in data, attempt to read the input from a file */
            if (256-dataLen > 1)
            {
                pFile = fopen(FILENAME, "r");
                if (pFile != NULL)
                {
                    /* POTENTIAL FLAW: Read data from a file */
                    if (fgets(data+dataLen, (int)(256-dataLen), pFile) == NULL)
                    {
                        printLine("fgets() failed");
                        /* Restore NUL terminator if fgets fails */
                        data[dataLen] = '\0';
                    }
                    fclose(pFile);
                }
            }
        }
    }
    return data;
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* The global variables below are used to drive control flow in the source functions. */
extern int CWE90_LDAP_Injection__w32_char_file_22_goodG2B1Global;
extern int CWE90_LDAP_Injection__w32_char_file_22_goodG2B2Global;

/* goodG2B1() - use goodsource and badsink by setting the static variable to false instead of true */
char * CWE90_LDAP_Injection__w32_char_file_22_goodG2B1Source(char * data)
{
    if(CWE90_LDAP_Injection__w32_char_file_22_goodG2B1Global)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        /* FIX: Use a fixed file name */
        strcat(data, "Doe, XXXXX");
    }
    return data;
}

/* goodG2B2() - use goodsource and badsink by reversing the blocks in the if in the source function */
char * CWE90_LDAP_Injection__w32_char_file_22_goodG2B2Source(char * data)
{
    if(CWE90_LDAP_Injection__w32_char_file_22_goodG2B2Global)
    {
        /* FIX: Use a fixed file name */
        strcat(data, "Doe, XXXXX");
    }
    return data;
}

#endif /* OMITGOOD */
