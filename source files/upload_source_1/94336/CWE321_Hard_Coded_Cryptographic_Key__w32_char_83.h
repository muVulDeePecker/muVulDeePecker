/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE321_Hard_Coded_Cryptographic_Key__w32_char_83.h
Label Definition File: CWE321_Hard_Coded_Cryptographic_Key__w32.label.xml
Template File: sources-sink-83.tmpl.h
*/
/*
 * @description
 * CWE: 321 Use of Hard-coded Cryptographic Key
 * BadSource:  Copy a hardcoded value into cryptoKey
 * GoodSource: Read cryptoKey from the console
 * Sinks:
 *    BadSink : Hash cryptoKey and use the value to encrypt a string
 * Flow Variant: 83 Data flow: data passed to class constructor and destructor by declaring the class object on the stack
 *
 * */

#include "std_testcase.h"

namespace CWE321_Hard_Coded_Cryptographic_Key__w32_char_83
{

#ifndef OMITBAD

class CWE321_Hard_Coded_Cryptographic_Key__w32_char_83_bad
{
public:
    CWE321_Hard_Coded_Cryptographic_Key__w32_char_83_bad(char * cryptoKeyCopy);
    ~CWE321_Hard_Coded_Cryptographic_Key__w32_char_83_bad();

private:
    char * cryptoKey;
};

#endif /* OMITBAD */

#ifndef OMITGOOD

class CWE321_Hard_Coded_Cryptographic_Key__w32_char_83_goodG2B
{
public:
    CWE321_Hard_Coded_Cryptographic_Key__w32_char_83_goodG2B(char * cryptoKeyCopy);
    ~CWE321_Hard_Coded_Cryptographic_Key__w32_char_83_goodG2B();

private:
    char * cryptoKey;
};

#endif /* OMITGOOD */

}
