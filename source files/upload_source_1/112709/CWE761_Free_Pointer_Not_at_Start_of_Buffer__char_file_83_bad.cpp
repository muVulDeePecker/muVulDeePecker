/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_file_83_bad.cpp
Label Definition File: CWE761_Free_Pointer_Not_at_Start_of_Buffer.label.xml
Template File: source-sinks-83_bad.tmpl.cpp
*/
/*
 * @description
 * CWE: 761 Free Pointer not at Start of Buffer
 * BadSource: file Read input from a file
 * Sinks:
 *    GoodSink: free() memory correctly at the start of the buffer
 *    BadSink : free() memory not at the start of the buffer
 * Flow Variant: 83 Data flow: data passed to class constructor and destructor by declaring the class object on the stack
 *
 * */
#ifndef OMITBAD

#include "std_testcase.h"
#include "CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_file_83.h"

#ifdef _WIN32
#define FILENAME "C:\\temp\\file.txt"
#else
#define FILENAME "/tmp/file.txt"
#endif

#define SEARCH_CHAR 'S'

namespace CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_file_83
{
CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_file_83_bad::CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_file_83_bad(char * dataCopy)
{
    data = dataCopy;
    {
        /* Read input from a file */
        size_t dataLen = strlen(data);
        FILE * pFile;
        /* if there is room in data, attempt to read the input from a file */
        if (100-dataLen > 1)
        {
            pFile = fopen(FILENAME, "r");
            if (pFile != NULL)
            {
                /* POTENTIAL FLAW: Read data from a file */
                if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL)
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

CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_file_83_bad::~CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_file_83_bad()
{
    /* FLAW: We are incrementing the pointer in the loop - this will cause us to free the
     * memory block not at the start of the buffer */
    for (; *data != '\0'; data++)
    {
        if (*data == SEARCH_CHAR)
        {
            printLine("We have a match!");
            break;
        }
    }
    free(data);
}
}
#endif /* OMITBAD */
