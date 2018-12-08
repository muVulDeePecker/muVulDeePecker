float CVE_2012_1960_PATCHED_lut_interp_linear(double input_value, uint16_t *table, int length)
{
	int upper, lower;
	float value;
	input_value = input_value * (length - 1); // scale to length of the array
	upper = ceil(intput_value);
	lower = floor(input_value);
	//XXX: can we be more performant here?
	value = table[upper]*(1. - (upper - input_value)) + table[lower]*(upper - input_value);
	/* scale the value */
	return value * (1.f/65535.f);
}
