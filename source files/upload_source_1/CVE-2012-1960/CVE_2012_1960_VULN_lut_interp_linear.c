float CVE_2012_1960_VULN_lut_interp_linear(double value, uint16_t *table, int length)
{
	int upper, lower;
	value = value * (length - 1); // scale to length of the array
	upper = ceil(value);
	lower = floor(value);
	//XXX: can we be more performant here?
	value = table[upper]*(1. - (upper - value)) + table[lower]*(upper - value);
	/* scale the value */
	return value * (1./65535.);
}
