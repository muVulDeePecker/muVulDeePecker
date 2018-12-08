float CVE_2012_1960_VULN_clamp_float(float a)
{
        if (a > 1.)
                return 1.;
        else if (a < 0)
                return 0;
        else
                return a;
}
