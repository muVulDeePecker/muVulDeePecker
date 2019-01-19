/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE114_Process_Control__w32_char_environment_82.h
Label Definition File: CWE114_Process_Control__w32.label.xml
Template File: sources-sink-82.tmpl.h
*/
/*
 * @description
 * CWE: 114 Process Control
 * BadSource: environment Read input from an environment variable
 * GoodSource: Hard code the full pathname to the library
 *    BadSink : Load a dynamic link library
 * Flow Variant: 82 Data flow: data passed in a parameter to an virtual method called via a pointer
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

namespace CWE114_Process_Control__w32_char_environment_82
{

class CWE114_Process_Control__w32_char_environment_82_base
{
public:
    /* pure virtual function */
    virtual void action(char * data) = 0;
};

#ifndef OMITBAD

class CWE114_Process_Control__w32_char_environment_82_bad : public CWE114_Process_Control__w32_char_environment_82_base
{
public:
    void action(char * data);
};

#endif /* OMITBAD */

#ifndef OMITGOOD

class CWE114_Process_Control__w32_char_environment_82_goodG2B : public CWE114_Process_Control__w32_char_environment_82_base
{
public:
    void action(char * data);
};

#endif /* OMITGOOD */

}
