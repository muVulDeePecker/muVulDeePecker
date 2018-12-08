BOOL
CVE_2013_1672_VULN_ProcessSoftwareUpdateCommand(DWORD argc, LPWSTR *argv)
{
  BOOL result = TRUE;
  if (argc < 3) {
    LOG_WARN(("Not enough command line parameters specified. "
              "Updating update.status."));

    // We can only update update.status if argv[1] exists.  argv[1] is
    // the directory where the update.status file exists.
    if (argc < 2 || 
        !WriteStatusFailure(argv[1], 
                            SERVICE_NOT_ENOUGH_COMMAND_LINE_ARGS)) {
      LOG_WARN(("Could not write update.status service update failure.  (%d)",
                GetLastError()));
    }
    return FALSE;
  }

  WCHAR installDir[MAX_PATH + 1] = {L'\0'};
  if (!GetInstallationDir(argc, argv, installDir)) {
    LOG_WARN(("Could not get the installation directory"));
    if (!WriteStatusFailure(argv[1],
                            SERVICE_INSTALLDIR_ERROR)) {
      LOG_WARN(("Could not write update.status for GetInstallationDir failure."));
    }
    return FALSE;
  }

  // Make sure the path to the updater to use for the update is local.
  // We do this check to make sure that file locking is available for
  // race condition security checks.
  BOOL isLocal = FALSE;
  if (!IsLocalFile(argv[0], isLocal) || !isLocal) {
    LOG_WARN(("Filesystem in path %ls is not supported (%d)",
              argv[0], GetLastError()));
    if (!WriteStatusFailure(argv[1], 
                            SERVICE_UPDATER_NOT_FIXED_DRIVE)) {
      LOG_WARN(("Could not write update.status service update failure.  (%d)",
                GetLastError()));
    }
    return FALSE;
  }

  nsAutoHandle noWriteLock(CreateFileW(argv[0], GENERIC_READ, FILE_SHARE_READ, 
                                       NULL, OPEN_EXISTING, 0, NULL));
  if (INVALID_HANDLE_VALUE == noWriteLock) {
      LOG_WARN(("Could not set no write sharing access on file.  (%d)",
                GetLastError()));
    if (!WriteStatusFailure(argv[1], 
                            SERVICE_COULD_NOT_LOCK_UPDATER)) {
      LOG_WARN(("Could not write update.status service update failure.  (%d)",
                GetLastError()));
    }
    return FALSE;
  }

  // Verify that the updater.exe that we are executing is the same
  // as the one in the installation directory which we are updating.
  // The installation dir that we are installing to is installDir.
  WCHAR installDirUpdater[MAX_PATH + 1] = {L'\0'};
  wcsncpy(installDirUpdater, installDir, MAX_PATH);
  if (!PathAppendSafe(installDirUpdater, L"updater.exe")) {
    LOG_WARN(("Install directory updater could not be determined."));
    result = FALSE;
  }

  BOOL updaterIsCorrect;
  if (result && !VerifySameFiles(argv[0], installDirUpdater, 
                                 updaterIsCorrect)) {
    LOG_WARN(("Error checking if the updaters are the same.\n"
              "Path 1: %ls\nPath 2: %ls", argv[0], installDirUpdater));
    result = FALSE;
  }

  if (result && !updaterIsCorrect) {
    LOG_WARN(("The updaters do not match, udpater will not run.")); 
    result = FALSE;
  }

  if (result) {
    LOG(("updater.exe was compared successfully to the installation directory"
         " updater.exe."));
  } else {
    if (!WriteStatusFailure(argv[1], 
                            SERVICE_UPDATER_COMPARE_ERROR)) {
      LOG_WARN(("Could not write update.status updater compare failure."));
    }
    return FALSE;
  }

  // Check to make sure the udpater.exe module has the unique updater identity.
  // This is a security measure to make sure that the signed executable that
  // we will run is actually an updater.
  HMODULE updaterModule = LoadLibraryEx(argv[0], NULL, 
                                        LOAD_LIBRARY_AS_DATAFILE);
  if (!updaterModule) {
    LOG_WARN(("updater.exe module could not be loaded. (%d)", GetLastError()));
    result = FALSE;
  } else {
    char updaterIdentity[64];
    if (!LoadStringA(updaterModule, IDS_UPDATER_IDENTITY, 
                     updaterIdentity, sizeof(updaterIdentity))) {
      LOG_WARN(("The updater.exe application does not contain the Mozilla"
                " updater identity."));
      result = FALSE;
    }

    if (strcmp(updaterIdentity, UPDATER_IDENTITY_STRING)) {
      LOG_WARN(("The updater.exe identity string is not valid."));
      result = FALSE;
    }
    FreeLibrary(updaterModule);
  }

  if (result) {
    LOG(("The updater.exe application contains the Mozilla"
          " updater identity."));
  } else {
    if (!WriteStatusFailure(argv[1], 
                            SERVICE_UPDATER_IDENTITY_ERROR)) {
      LOG_WARN(("Could not write update.status no updater identity."));
    }
    return TRUE;
  }

  // Check for updater.exe sign problems
  BOOL updaterSignProblem = FALSE;
#ifndef DISABLE_UPDATER_AUTHENTICODE_CHECK
  updaterSignProblem = !DoesBinaryMatchAllowedCertificates(installDir,
                                                           argv[0]);
#endif

  // Only proceed with the update if we have no signing problems
  if (!updaterSignProblem) {
    BOOL updateProcessWasStarted = FALSE;
    if (StartUpdateProcess(argc, argv, installDir,
                           updateProcessWasStarted)) {
      LOG(("updater.exe was launched and run successfully!"));
      LogFlush();

      // Don't attempt to update the service when the update is being staged.
      if (!IsUpdateBeingStaged(argc, argv)) {
        // We might not execute code after StartServiceUpdate because
        // the service installer will stop the service if it is running.
        StartServiceUpdate(installDir);
      }
    } else {
      result = FALSE;
      LOG_WARN(("Error running update process. Updating update.status  (%d)",
                GetLastError()));
      LogFlush();

      // If the update process was started, then updater.exe is responsible for
      // setting the failure code.  If it could not be started then we do the 
      // work.  We set an error instead of directly setting status pending 
      // so that the app.update.service.errors pref can be updated when 
      // the callback app restarts.
      if (!updateProcessWasStarted) {
        if (!WriteStatusFailure(argv[1], 
                                SERVICE_UPDATER_COULD_NOT_BE_STARTED)) {
          LOG_WARN(("Could not write update.status service update failure.  (%d)",
                    GetLastError()));
        }
      }
    }
  } else {
    result = FALSE;
    LOG_WARN(("Could not start process due to certificate check error on "
              "updater.exe. Updating update.status.  (%d)", GetLastError()));

    // When there is a certificate check error on the updater.exe application,
    // we want to write out the error.
    if (!WriteStatusFailure(argv[1], 
                            SERVICE_UPDATER_SIGN_ERROR)) {
      LOG_WARN(("Could not write pending state to update.status.  (%d)",
                GetLastError()));
    }
  }

  return result;
}
