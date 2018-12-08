float CVE_2012_1960_PATCHED_clamp_float(float a)
{
	/* One would naturally write this function as the following:
	if (a > 1.)
		return 1.;
	else if (a < 0)
		return 0;
	else
		return a;

	However, that version will let NaNs pass through which is undesirable
	for most consumers.
	*/

	if (a > 1.)
		return 1.;
	else if (a >= 0)
		return a;
	else // a < 0 or a is NaN
		return 0;
}
