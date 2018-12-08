BOOL
CVE_2013_1673_VULN_FixServicePath(SC_HANDLE service,
               LPCWSTR currentServicePath,
               BOOL &servicePathWasWrong)
{
  // When we originally upgraded the MozillaMaintenance service we
  // would uninstall the service on each upgrade.  This had an
  // intermittent error which could cause the service to use the file
  // maintenanceservice_tmp.exe as the install path.  Only a small number
  // of Nightly users would be affected by this, but we check for this
  // state here and fix the user if they are affected.
  bool doesServiceHaveCorrectPath =
    !wcsstr(currentServicePath, L"maintenanceservice_tmp.exe");
  if (doesServiceHaveCorrectPath) {
    LOG(("The MozillaMaintenance service path is correct."));
    servicePathWasWrong = FALSE;
    return TRUE;
  }
  // This is a recoverable situation so not logging as a warning
  LOG(("The MozillaMaintenance path is NOT correct."));
  servicePathWasWrong = TRUE;

  WCHAR fixedPath[MAX_PATH + 1] = { L'\0' };
  wcsncpy(fixedPath, currentServicePath, MAX_PATH);
  PathUnquoteSpacesW(fixedPath);
  if (!PathRemoveFileSpecW(fixedPath)) {
    LOG_WARN(("Couldn't remove file spec.  (%d)", GetLastError()));
    return FALSE;
  }
  if (!PathAppendSafe(fixedPath, L"maintenanceservice.exe")) {
    LOG_WARN(("Couldn't append file spec.  (%d)", GetLastError()));
    return FALSE;
  }
  PathQuoteSpacesW(fixedPath);


  if (!ChangeServiceConfigW(service, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                            SERVICE_NO_CHANGE, fixedPath, NULL, NULL, NULL,
                            NULL, NULL, NULL)) {
    LOG_WARN(("Could not fix service path.  (%d)", GetLastError()));
    return FALSE;
  }

  LOG(("Fixed service path to: %ls.", fixedPath));
  return TRUE;
}
