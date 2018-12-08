MarFile *CVE_2013_1726_VULN_mar_wopen(const wchar_t *path) {
  FILE *fp;

  fp = _wfopen(path, L"rb");
  if (!fp)
    return NULL;

  return mar_fpopen(fp);
}
