MarFile *CVE_2013_1726_PATCHED_mar_wopen(const wchar_t *path) {
  FILE *fp;

  _wfopen_s(&fp, path, L"rb");
  if (!fp)
    return NULL;

  return mar_fpopen(fp);
}
