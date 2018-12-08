void CVE_2012_1960_VULN_compute_curve_gamma_table_type1(float gamma_table[256], double gamma)
{
	unsigned int i;
	for (i = 0; i < 256; i++) {
		gamma_table[i] = pow(i/255., gamma);
	}
}
