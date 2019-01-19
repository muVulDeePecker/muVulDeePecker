/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE134_Uncontrolled_Format_String__char_console_vprintf_84_goodB2G.cpp
Label Definition File: CWE134_Uncontrolled_Format_String.vasinks.label.xml
Template File: sources-vasinks-84_goodB2G.tmpl.cpp
*/
/*
 * @description
 * CWE: 134 Uncontrolled Format String
 * BadSource: console Read input from the console
 * GoodSource: Copy a fixed string into data
 * Sinks: vprintf
 *    GoodSink: vprintf with a format string
 *    BadSink : vprintf without a format string
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */
#ifndef OMITGOOD

#include <stdarg.h>
#include "std_testcase.h"
#include "CWE134_Uncontrolled_Format_String__char_console_vprintf_84.h"

namespace CWE134_Uncontrolled_Format_String__char_console_vprintf_84
{
CWE134_Uncontrolled_Format_String__char_console_vprintf_84_goodB2G::CWE134_Uncontrolled_Format_String__char_console_vprintf_84_goodB2G(char * dataCopy)
{
    data = dataCopy;
    {
        /* Read input from the console */
        size_t dataLen = strlen(data);
        /* if there is room in data, read into it from the console */
        if (100-dataLen > 1)
        {
            /* POTENTIAL FLAW: Read data from the console */
            if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL)
            {
                /* The next few lines remove the carriage return from the string that is
                 * inserted by fgets() */
                dataLen = strlen(data);
                if (dataLen > 0 && data[dataLen-1] == '\n')
                {
                    data[dataLen-1] = '\0';
                }
            }
            else
            {
                printLine("fgets() failed");
                /* Restore NUL terminator if fgets fails */
                data[dataLen] = '\0';
            }
        }
    }
}

static void goodB2GVaSink(char * data, ...)
{
    {
        va_list args;
        va_start(args, data);
        /* FIX: Specify the format disallowing a format string vulnerability */
        vprintf("%s", args);
        va_end(args);
    }
}

CWE134_Uncontrolled_Format_String__char_console_vprintf_84_goodB2G::~CWE134_Uncontrolled_Format_String__char_console_vprintf_84_goodB2G()
{
    goodB2GVaSink(data, data);
}
}
#endif /* OMITGOOD */
