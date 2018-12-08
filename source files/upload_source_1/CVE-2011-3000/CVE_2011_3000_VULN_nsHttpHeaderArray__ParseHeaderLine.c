void
CVE_2011_3000_VULN_nsHttpHeaderArray::ParseHeaderLine(const char *line,
                                   nsHttpAtom *hdr,
                                   char **val)
{
    //
    // BNF from section 4.2 of RFC 2616:
    //
    //   message-header = field-name ":" [ field-value ]
    //   field-name     = token
    //   field-value    = *( field-content | LWS )
    //   field-content  = <the OCTETs making up the field-value
    //                     and consisting of either *TEXT or combinations
    //                     of token, separators, and quoted-string>
    //
    
    // We skip over mal-formed headers in the hope that we'll still be able to
    // do something useful with the response.

    char *p = (char *) strchr(line, ':');
    if (!p) {
        LOG(("malformed header [%s]: no colon\n", line));
        return;
    }

    // make sure we have a valid token for the field-name
    if (!nsHttp::IsValidToken(line, p)) {
        LOG(("malformed header [%s]: field-name not a token\n", line));
        return;
    }
    
    *p = 0; // null terminate field-name

    nsHttpAtom atom = nsHttp::ResolveAtom(line);
    if (!atom) {
        LOG(("failed to resolve atom [%s]\n", line));
        return;
    }

    // skip over whitespace
    p = net_FindCharNotInSet(++p, HTTP_LWS);

    // trim trailing whitespace - bug 86608
    char *p2 = net_RFindCharNotInSet(p, HTTP_LWS);

    *++p2 = 0; // null terminate header value; if all chars starting at |p|
               // consisted of LWS, then p2 would have pointed at |p-1|, so
               // the prefix increment is always valid.

    // assign return values
    if (hdr) *hdr = atom;
    if (val) *val = p;

    // assign response header
    SetHeader(atom, nsDependentCString(p, p2 - p), PR_TRUE);
}
