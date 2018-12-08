static void CVE_2007_1217_VULN_bufprint(char *fmt,...)
{
	va_list f;
	va_start(f, fmt);
	vsprintf(p, fmt, f);
	va_end(f);
	p += strlen(p);
}
