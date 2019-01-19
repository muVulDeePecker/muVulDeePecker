/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE369_Divide_by_Zero__float_listenSocket_81_goodG2B.cpp
Label Definition File: CWE369_Divide_by_Zero__float.label.xml
Template File: sources-sinks-81_goodG2B.tmpl.cpp
*/
/*
 * @description
 * CWE: 369 Divide by Zero
 * BadSource: listenSocket Read data using a listen socket (server side)
 * GoodSource: A hardcoded non-zero number (two)
 * Sinks:
 *    GoodSink: Check value of or near zero before dividing
 *    BadSink : Divide a constant by data
 * Flow Variant: 81 Data flow: data passed in a parameter to an virtual method called via a reference
 *
 * */
#ifndef OMITGOOD

#include "std_testcase.h"
#include "CWE369_Divide_by_Zero__float_listenSocket_81.h"

namespace CWE369_Divide_by_Zero__float_listenSocket_81
{

void CWE369_Divide_by_Zero__float_listenSocket_81_goodG2B::action(float data) const
{
    {
        /* POTENTIAL FLAW: Possibly divide by zero */
        int result = (int)(100.0 / data);
        printIntLine(result);
    }
}

}
#endif /* OMITGOOD */
