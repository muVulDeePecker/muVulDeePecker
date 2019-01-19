/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE90_LDAP_Injection__w32_char_console_33.cpp
Label Definition File: CWE90_LDAP_Injection__w32.label.xml
Template File: sources-sink-33.tmpl.cpp
*/
/*
 * @description
 * CWE: 90 LDAP Injection
 * BadSource: console Read input from the console
 * GoodSource: Use a fixed string
 * Sinks:
 *    BadSink : data concatenated into LDAP search, which could result in LDAP Injection
 * Flow Variant: 33 Data flow: use of a C++ reference to data within the same function
 *
 * */

#include "std_testcase.h"

#include <windows.h>
#include <Winldap.h>

#pragma comment(lib, "wldap32")

namespace CWE90_LDAP_Injection__w32_char_console_33
{

#ifndef OMITBAD

void bad()
{
    char * data;
    char * &dataRef = data;
    char dataBuffer[256] = "";
    data = dataBuffer;
    {
        /* Read input from the console */
        size_t dataLen = strlen(data);
        /* if there is room in data, read into it from the console */
        if (256-dataLen > 1)
        {
            /* POTENTIAL FLAW: Read data from the console */
            if (fgets(data+dataLen, (int)(256-dataLen), stdin) != NULL)
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
    {
        char * data = dataRef;
        {
            LDAP* pLdapConnection = NULL;
            ULONG connectSuccess = 0L;
            ULONG searchSuccess = 0L;
            LDAPMessage *pMessage = NULL;
            char filter[256];
            /* POTENTIAL FLAW: data concatenated into LDAP search, which could result in LDAP Injection*/
            _snprintf(filter, 256-1, "(cn=%s)", data);
            pLdapConnection = ldap_initA("localhost", LDAP_PORT);
            if (pLdapConnection == NULL)
            {
                printLine("Initialization failed");
                exit(1);
            }
            connectSuccess = ldap_connect(pLdapConnection, NULL);
            if (connectSuccess != LDAP_SUCCESS)
            {
                printLine("Connection failed");
                exit(1);
            }
            searchSuccess = ldap_search_ext_sA(
                                pLdapConnection,
                                "base",
                                LDAP_SCOPE_SUBTREE,
                                filter,
                                NULL,
                                0,
                                NULL,
                                NULL,
                                LDAP_NO_LIMIT,
                                LDAP_NO_LIMIT,
                                &pMessage);
            if (searchSuccess != LDAP_SUCCESS)
            {
                printLine("Search failed");
                if (pMessage != NULL)
                {
                    ldap_msgfree(pMessage);
                }
                exit(1);
            }
            /* Typically you would do something with the search results, but this is a test case and we can ignore them */
            /* Free the results to avoid incidentals */
            if (pMessage != NULL)
            {
                ldap_msgfree(pMessage);
            }
            /* Close the connection */
            ldap_unbind(pLdapConnection);
        }
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B() uses the GoodSource with the BadSink */
static void goodG2B()
{
    char * data;
    char * &dataRef = data;
    char dataBuffer[256] = "";
    data = dataBuffer;
    /* FIX: Use a fixed file name */
    strcat(data, "Doe, XXXXX");
    {
        char * data = dataRef;
        {
            LDAP* pLdapConnection = NULL;
            ULONG connectSuccess = 0L;
            ULONG searchSuccess = 0L;
            LDAPMessage *pMessage = NULL;
            char filter[256];
            /* POTENTIAL FLAW: data concatenated into LDAP search, which could result in LDAP Injection*/
            _snprintf(filter, 256-1, "(cn=%s)", data);
            pLdapConnection = ldap_initA("localhost", LDAP_PORT);
            if (pLdapConnection == NULL)
            {
                printLine("Initialization failed");
                exit(1);
            }
            connectSuccess = ldap_connect(pLdapConnection, NULL);
            if (connectSuccess != LDAP_SUCCESS)
            {
                printLine("Connection failed");
                exit(1);
            }
            searchSuccess = ldap_search_ext_sA(
                                pLdapConnection,
                                "base",
                                LDAP_SCOPE_SUBTREE,
                                filter,
                                NULL,
                                0,
                                NULL,
                                NULL,
                                LDAP_NO_LIMIT,
                                LDAP_NO_LIMIT,
                                &pMessage);
            if (searchSuccess != LDAP_SUCCESS)
            {
                printLine("Search failed");
                if (pMessage != NULL)
                {
                    ldap_msgfree(pMessage);
                }
                exit(1);
            }
            /* Typically you would do something with the search results, but this is a test case and we can ignore them */
            /* Free the results to avoid incidentals */
            if (pMessage != NULL)
            {
                ldap_msgfree(pMessage);
            }
            /* Close the connection */
            ldap_unbind(pLdapConnection);
        }
    }
}

void good()
{
    goodG2B();
}

#endif /* OMITGOOD */

} /* close namespace */

/* Below is the main(). It is only used when building this testcase on
 * its own for testing or for building a binary to use in testing binary
 * analysis tools. It is not used when compiling all the testcases as one
 * application, which is how source code analysis tools are tested.
 */
#ifdef INCLUDEMAIN

using namespace CWE90_LDAP_Injection__w32_char_console_33; /* so that we can use good and bad easily */

int main(int argc, char * argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
    printLine("Calling good()...");
    good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
