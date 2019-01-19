/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_console_84.h
Label Definition File: CWE761_Free_Pointer_Not_at_Start_of_Buffer.label.xml
Template File: source-sinks-84.tmpl.h
*/
/*
 * @description
 * CWE: 761 Free Pointer not at Start of Buffer
 * BadSource: console Read input from the console
 * Sinks:
 *    GoodSink: free() memory correctly at the start of the buffer
 *    BadSink : free() memory not at the start of the buffer
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

namespace CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_console_84
{

#ifndef OMITBAD

class CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_console_84_bad
{
public:
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_console_84_bad(char * dataCopy);
    ~CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_console_84_bad();

private:
    char * data;
};

#endif /* OMITBAD */

#ifndef OMITGOOD

class CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_console_84_goodB2G
{
public:
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_console_84_goodB2G(char * dataCopy);
    ~CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_console_84_goodB2G();

private:
    char * data;
};

#endif /* OMITGOOD */

}
