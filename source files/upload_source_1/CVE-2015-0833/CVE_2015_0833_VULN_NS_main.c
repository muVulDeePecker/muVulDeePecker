int CVE_2015_0833_VULN_NS_main(int argc, NS_tchar **argv)
{
#if defined(MOZ_WIDGET_GONK)
  if (getenv("LD_PRELOAD")) {
    // If the updater is launched with LD_PRELOAD set, then we wind up
    // preloading libmozglue.so. Under some circumstances, this can cause
    // the remount of /system to fail when going from rw to ro, so if we
    // detect LD_PRELOAD we unsetenv it and relaunch ourselves without it.
    // This will cause the offending preloaded library to be closed.
    //
    // For a variety of reasons, this is really hard to do in a safe manner
    // in the parent process, so we do it here.
    unsetenv("LD_PRELOAD");
    execv(argv[0], argv);
    __android_log_print(ANDROID_LOG_INFO, "updater",
                        "execve failed: errno: %d. Exiting...", errno);
    _exit(1);
  }
#endif
  InitProgressUI(&argc, &argv);

  // To process an update the updater command line must at a minimum have the
  // directory path containing the updater.mar file to process as the first
  // argument, the install directory as the second argument, and the directory
  // to apply the update to as the third argument. When the updater is launched
  // by another process the PID of the parent process should be provided in the
  // optional fourth argument and the updater will wait on the parent process to
  // exit if the value is non-zero and the process is present. This is necessary
  // due to not being able to update files that are in use on Windows. The
  // optional fifth argument is the callback's working directory and the
  // optional sixth argument is the callback path. The callback is the
  // application to launch after updating and it will be launched when these
  // arguments are provided whether the update was successful or not. All
  // remaining arguments are optional and are passed to the callback when it is
  // launched.
  if (argc < 4) {
    fprintf(stderr, "Usage: updater patch-dir install-dir apply-to-dir [wait-pid [callback-working-dir callback-path args...]]\n");
    return 1;
  }

  // The directory containing the update information.
  gPatchDirPath = argv[1];
  // The directory we're going to update to.
  // We copy this string because we need to remove trailing slashes.  The C++
  // standard says that it's always safe to write to strings pointed to by argv
  // elements, but I don't necessarily believe it.
  NS_tstrncpy(gInstallDirPath, argv[2], MAXPATHLEN);
  gInstallDirPath[MAXPATHLEN - 1] = NS_T('\0');
  NS_tchar *slash = NS_tstrrchr(gInstallDirPath, NS_SLASH);
  if (slash && !slash[1]) {
    *slash = NS_T('\0');
  }

#ifdef XP_WIN
  bool useService = false;
  bool testOnlyFallbackKeyExists = false;
  bool noServiceFallback = getenv("MOZ_NO_SERVICE_FALLBACK") != nullptr;
  putenv(const_cast<char*>("MOZ_NO_SERVICE_FALLBACK="));

  // We never want the service to be used unless we build with
  // the maintenance service.
#ifdef MOZ_MAINTENANCE_SERVICE
  useService = IsUpdateStatusPendingService();
  // Our tests run with a different apply directory for each test.
  // We use this registry key on our test slaves to store the
  // allowed name/issuers.
  testOnlyFallbackKeyExists = DoesFallbackKeyExist();
#endif

  // Remove everything except close window from the context menu
  {
    HKEY hkApp;
    RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Classes\\Applications",
                    0, nullptr, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr,
                    &hkApp, nullptr);
    RegCloseKey(hkApp);
    if (RegCreateKeyExW(HKEY_CURRENT_USER,
                        L"Software\\Classes\\Applications\\updater.exe",
                        0, nullptr, REG_OPTION_VOLATILE, KEY_SET_VALUE, nullptr,
                        &hkApp, nullptr) == ERROR_SUCCESS) {
      RegSetValueExW(hkApp, L"IsHostApp", 0, REG_NONE, 0, 0);
      RegSetValueExW(hkApp, L"NoOpenWith", 0, REG_NONE, 0, 0);
      RegSetValueExW(hkApp, L"NoStartPage", 0, REG_NONE, 0, 0);
      RegCloseKey(hkApp);
    }
  }
#endif

  // If there is a PID specified and it is not '0' then wait for the process to exit.
#ifdef XP_WIN
  __int64 pid = 0;
#else
  int pid = 0;
#endif
  if (argc > 4) {
#ifdef XP_WIN
    pid = _wtoi64(argv[4]);
#else
    pid = atoi(argv[4]);
#endif
    if (pid == -1) {
      // This is a signal from the parent process that the updater should stage
      // the update.
      sStagedUpdate = true;
    } else if (NS_tstrstr(argv[4], NS_T("/replace"))) {
      // We're processing a request to replace the application with a staged
      // update.
      sReplaceRequest = true;
    }
  }

  // The directory we're going to update to.
  // We copy this string because we need to remove trailing slashes.  The C++
  // standard says that it's always safe to write to strings pointed to by argv
  // elements, but I don't necessarily believe it.
  NS_tstrncpy(gWorkingDirPath, argv[3], MAXPATHLEN);
  gWorkingDirPath[MAXPATHLEN - 1] = NS_T('\0');
  slash = NS_tstrrchr(gWorkingDirPath, NS_SLASH);
  if (slash && !slash[1]) {
    *slash = NS_T('\0');
  }

  if (getenv("MOZ_OS_UPDATE")) {
    sIsOSUpdate = true;
    putenv(const_cast<char*>("MOZ_OS_UPDATE="));
  }

  if (sReplaceRequest) {
    // If we're attempting to replace the application, try to append to the
    // log generated when staging the staged update.
#ifdef XP_WIN
    NS_tchar* logDir = gPatchDirPath;
#else
#ifdef XP_MACOSX
    NS_tchar* logDir = gPatchDirPath;
#else
    NS_tchar logDir[MAXPATHLEN];
    NS_tsnprintf(logDir, sizeof(logDir)/sizeof(logDir[0]),
                 NS_T("%s/updated/updates"),
                 gInstallDirPath);
#endif
#endif

    LogInitAppend(logDir, NS_T("last-update.log"), NS_T("update.log"));
  } else {
    LogInit(gPatchDirPath, NS_T("update.log"));
  }

  if (!WriteStatusFile("applying")) {
    LOG(("failed setting status to 'applying'"));
    return 1;
  }

  if (sStagedUpdate) {
    LOG(("Performing a staged update"));
  } else if (sReplaceRequest) {
    LOG(("Performing a replace request"));
  }

  LOG(("PATCH DIRECTORY " LOG_S, gPatchDirPath));
  LOG(("INSTALLATION DIRECTORY " LOG_S, gInstallDirPath));
  LOG(("WORKING DIRECTORY " LOG_S, gWorkingDirPath));

#ifdef MOZ_WIDGET_GONK
  const char *prioEnv = getenv("MOZ_UPDATER_PRIO");
  if (prioEnv) {
    int32_t prioVal;
    int32_t oomScoreAdj;
    int32_t ioprioClass;
    int32_t ioprioLevel;
    if (sscanf(prioEnv, "%d/%d/%d/%d",
               &prioVal, &oomScoreAdj, &ioprioClass, &ioprioLevel) == 4) {
      LOG(("MOZ_UPDATER_PRIO=%s", prioEnv));
      if (setpriority(PRIO_PROCESS, 0, prioVal)) {
        LOG(("setpriority(%d) failed, errno = %d", prioVal, errno));
      }
      if (ioprio_set(IOPRIO_WHO_PROCESS, 0,
                     IOPRIO_PRIO_VALUE(ioprioClass, ioprioLevel))) {
        LOG(("ioprio_set(%d,%d) failed: errno = %d",
             ioprioClass, ioprioLevel, errno));
      }
      FILE *fs = fopen("/proc/self/oom_score_adj", "w");
      if (fs) {
        fprintf(fs, "%d", oomScoreAdj);
        fclose(fs);
      } else {
        LOG(("Unable to open /proc/self/oom_score_adj for writing, errno = %d", errno));
      }
    }
  }
#endif

#ifdef XP_WIN
  if (pid > 0) {
    HANDLE parent = OpenProcess(SYNCHRONIZE, false, (DWORD) pid);
    // May return nullptr if the parent process has already gone away.
    // Otherwise, wait for the parent process to exit before starting the
    // update.
    if (parent) {
      bool updateFromMetro = false;
#ifdef MOZ_METRO
      updateFromMetro = IsUpdateFromMetro(argc, argv);
#endif
      DWORD waitTime = updateFromMetro ?
                       IMMERSIVE_PARENT_WAIT : PARENT_WAIT;
      DWORD result = WaitForSingleObject(parent, waitTime);
      CloseHandle(parent);
      if (result != WAIT_OBJECT_0 && !updateFromMetro)
        return 1;
    }
  }
#else
  if (pid > 0)
    waitpid(pid, nullptr, 0);
#endif

  if (sReplaceRequest) {
#ifdef XP_WIN
    // On Windows, the current working directory of the process should be changed
    // so that it's not locked.
    NS_tchar tmpDir[MAXPATHLEN];
    if (GetTempPathW(MAXPATHLEN, tmpDir)) {
      NS_tchdir(tmpDir);
    }
#endif
  }

  // The callback is the remaining arguments starting at callbackIndex.
  // The argument specified by callbackIndex is the callback executable and the
  // argument prior to callbackIndex is the working directory.
  const int callbackIndex = 6;

#if defined(XP_WIN)
  sUsingService = getenv("MOZ_USING_SERVICE") != nullptr;
  putenv(const_cast<char*>("MOZ_USING_SERVICE="));
  // lastFallbackError keeps track of the last error for the service not being
  // used, in case of an error when fallback is not enabled we write the
  // error to the update.status file.
  // When fallback is disabled (MOZ_NO_SERVICE_FALLBACK does not exist) then
  // we will instead fallback to not using the service and display a UAC prompt.
  int lastFallbackError = FALLBACKKEY_UNKNOWN_ERROR;

  // Launch a second instance of the updater with the runas verb on Windows
  // when write access is denied to the installation directory.
  HANDLE updateLockFileHandle = INVALID_HANDLE_VALUE;
  NS_tchar elevatedLockFilePath[MAXPATHLEN] = {NS_T('\0')};
  if (!sUsingService &&
      (argc > callbackIndex || sStagedUpdate || sReplaceRequest)) {
    NS_tchar updateLockFilePath[MAXPATHLEN];
    if (sStagedUpdate) {
      // When staging an update, the lock file is:
      // <install_dir>\updated.update_in_progress.lock
      NS_tsnprintf(updateLockFilePath,
                   sizeof(updateLockFilePath)/sizeof(updateLockFilePath[0]),
                   NS_T("%s/updated.update_in_progress.lock"), gInstallDirPath);
    } else if (sReplaceRequest) {
      // When processing a replace request, the lock file is:
      // <install_dir>\..\moz_update_in_progress.lock
      NS_tchar installDir[MAXPATHLEN];
      NS_tstrcpy(installDir, gInstallDirPath);
      NS_tchar *slash = (NS_tchar *) NS_tstrrchr(installDir, NS_SLASH);
      *slash = NS_T('\0');
      NS_tsnprintf(updateLockFilePath,
                   sizeof(updateLockFilePath)/sizeof(updateLockFilePath[0]),
                   NS_T("%s\\moz_update_in_progress.lock"), installDir);
    } else {
      // In the non-staging update case, the lock file is:
      // <install_dir>\<app_name>.exe.update_in_progress.lock
      NS_tsnprintf(updateLockFilePath,
                   sizeof(updateLockFilePath)/sizeof(updateLockFilePath[0]),
                   NS_T("%s.update_in_progress.lock"), argv[callbackIndex]);
    }

    // The update_in_progress.lock file should only exist during an update. In
    // case it exists attempt to remove it and exit if that fails to prevent
    // simultaneous updates occurring.
    if (!_waccess(updateLockFilePath, F_OK) &&
        NS_tremove(updateLockFilePath) != 0) {
      // Try to fall back to the old way of doing updates if a staged
      // update fails.
      if (sStagedUpdate || sReplaceRequest) {
        // Note that this could fail, but if it does, there isn't too much we
        // can do in order to recover anyways.
        WriteStatusFile("pending");
      }
      LOG(("Update already in progress! Exiting"));
      return 1;
    }

    updateLockFileHandle = CreateFileW(updateLockFilePath,
                                       GENERIC_READ | GENERIC_WRITE,
                                       0,
                                       nullptr,
                                       OPEN_ALWAYS,
                                       FILE_FLAG_DELETE_ON_CLOSE,
                                       nullptr);

    NS_tsnprintf(elevatedLockFilePath,
                 sizeof(elevatedLockFilePath)/sizeof(elevatedLockFilePath[0]),
                 NS_T("%s/update_elevated.lock"), gPatchDirPath);

    // Even if a file has no sharing access, you can still get its attributes
    bool startedFromUnelevatedUpdater =
      GetFileAttributesW(elevatedLockFilePath) != INVALID_FILE_ATTRIBUTES;

    // If we're running from the service, then we were started with the same
    // token as the service so the permissions are already dropped.  If we're
    // running from an elevated updater that was started from an unelevated
    // updater, then we drop the permissions here. We do not drop the
    // permissions on the originally called updater because we use its token
    // to start the callback application.
    if(startedFromUnelevatedUpdater) {
      // Disable every privilege we don't need. Processes started using
      // CreateProcess will use the same token as this process.
      UACHelper::DisablePrivileges(nullptr);
    }

    if (updateLockFileHandle == INVALID_HANDLE_VALUE ||
        (useService && testOnlyFallbackKeyExists && noServiceFallback)) {
      if (!_waccess(elevatedLockFilePath, F_OK) &&
          NS_tremove(elevatedLockFilePath) != 0) {
        fprintf(stderr, "Unable to create elevated lock file! Exiting\n");
        return 1;
      }

      HANDLE elevatedFileHandle;
      elevatedFileHandle = CreateFileW(elevatedLockFilePath,
                                       GENERIC_READ | GENERIC_WRITE,
                                       0,
                                       nullptr,
                                       OPEN_ALWAYS,
                                       FILE_FLAG_DELETE_ON_CLOSE,
                                       nullptr);

      if (elevatedFileHandle == INVALID_HANDLE_VALUE) {
        LOG(("Unable to create elevated lock file! Exiting"));
        return 1;
      }

      wchar_t *cmdLine = MakeCommandLine(argc - 1, argv + 1);
      if (!cmdLine) {
        CloseHandle(elevatedFileHandle);
        return 1;
      }

      // Make sure the path to the updater to use for the update is on local.
      // We do this check to make sure that file locking is available for
      // race condition security checks.
      if (useService) {
        BOOL isLocal = FALSE;
        useService = IsLocalFile(argv[0], isLocal) && isLocal;
      }

      // If we have unprompted elevation we should NOT use the service
      // for the update. Service updates happen with the SYSTEM account
      // which has more privs than we need to update with.
      // Windows 8 provides a user interface so users can configure this
      // behavior and it can be configured in the registry in all Windows
      // versions that support UAC.
      if (useService) {
        BOOL unpromptedElevation;
        if (IsUnpromptedElevation(unpromptedElevation)) {
          useService = !unpromptedElevation;
        }
      }

      // Make sure the service registry entries for the instsallation path
      // are available.  If not don't use the service.
      if (useService) {
        WCHAR maintenanceServiceKey[MAX_PATH + 1];
        if (CalculateRegistryPathFromFilePath(gInstallDirPath, maintenanceServiceKey)) {
          HKEY baseKey;
          if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            maintenanceServiceKey, 0,
                            KEY_READ | KEY_WOW64_64KEY,
                            &baseKey) == ERROR_SUCCESS) {
            RegCloseKey(baseKey);
          } else {
            useService = testOnlyFallbackKeyExists;
            if (!useService) {
              lastFallbackError = FALLBACKKEY_NOKEY_ERROR;
            }
          }
        } else {
          useService = false;
          lastFallbackError = FALLBACKKEY_REGPATH_ERROR;
        }
      }

      // Originally we used to write "pending" to update.status before
      // launching the service command.  This is no longer needed now
      // since the service command is launched from updater.exe.  If anything
      // fails in between, we can fall back to using the normal update process
      // on our own.

      // If we still want to use the service try to launch the service
      // comamnd for the update.
      if (useService) {
        // If the update couldn't be started, then set useService to false so
        // we do the update the old way.
        DWORD ret = LaunchServiceSoftwareUpdateCommand(argc, (LPCWSTR *)argv);
        useService = (ret == ERROR_SUCCESS);
        // If the command was launched then wait for the service to be done.
        if (useService) {
          bool showProgressUI = false;
          // Never show the progress UI when staging updates.
          if (!sStagedUpdate) {
            // We need to call this separately instead of allowing ShowProgressUI
            // to initialize the strings because the service will move the
            // ini file out of the way when running updater.
            showProgressUI = !InitProgressUIStrings();
          }

          // Wait for the service to stop for 5 seconds.  If the service
          // has still not stopped then show an indeterminate progress bar.
          DWORD lastState = WaitForServiceStop(SVC_NAME, 5);
          if (lastState != SERVICE_STOPPED) {
            Thread t1;
            if (t1.Run(WaitForServiceFinishThread, nullptr) == 0 &&
                showProgressUI) {
              ShowProgressUI(true, false);
            }
            t1.Join();
          }

          lastState = WaitForServiceStop(SVC_NAME, 1);
          if (lastState != SERVICE_STOPPED) {
            // If the service doesn't stop after 10 minutes there is
            // something seriously wrong.
            lastFallbackError = FALLBACKKEY_SERVICE_NO_STOP_ERROR;
            useService = false;
          }
        } else {
          lastFallbackError = FALLBACKKEY_LAUNCH_ERROR;
        }
      }

      // If the service can't be used when staging and update, make sure that
      // the UAC prompt is not shown! In this case, just set the status to
      // pending and the update will be applied during the next startup.
      if (!useService && sStagedUpdate) {
        if (updateLockFileHandle != INVALID_HANDLE_VALUE) {
          CloseHandle(updateLockFileHandle);
        }
        WriteStatusPending(gPatchDirPath);
        return 0;
      }

      // If we started the service command, and it finished, check the
      // update.status file to make sure it succeeded, and if it did
      // we need to manually start the PostUpdate process from the
      // current user's session of this unelevated updater.exe the
      // current process is running as.
      // Note that we don't need to do this if we're just staging the update,
      // as the PostUpdate step runs when performing the replacing in that case.
      if (useService && !sStagedUpdate) {
        bool updateStatusSucceeded = false;
        if (IsUpdateStatusSucceeded(updateStatusSucceeded) &&
            updateStatusSucceeded) {
          if (!LaunchWinPostProcess(gInstallDirPath, gPatchDirPath, false, nullptr)) {
            fprintf(stderr, "The post update process which runs as the user"
                    " for service update could not be launched.");
          }
        }
      }

      // If we didn't want to use the service at all, or if an update was
      // already happening, or launching the service command failed, then
      // launch the elevated updater.exe as we do without the service.
      // We don't launch the elevated updater in the case that we did have
      // write access all along because in that case the only reason we're
      // using the service is because we are testing.
      if (!useService && !noServiceFallback &&
          updateLockFileHandle == INVALID_HANDLE_VALUE) {
        SHELLEXECUTEINFO sinfo;
        memset(&sinfo, 0, sizeof(SHELLEXECUTEINFO));
        sinfo.cbSize       = sizeof(SHELLEXECUTEINFO);
        sinfo.fMask        = SEE_MASK_FLAG_NO_UI |
                             SEE_MASK_FLAG_DDEWAIT |
                             SEE_MASK_NOCLOSEPROCESS;
        sinfo.hwnd         = nullptr;
        sinfo.lpFile       = argv[0];
        sinfo.lpParameters = cmdLine;
        sinfo.lpVerb       = L"runas";
        sinfo.nShow        = SW_SHOWNORMAL;

        bool result = ShellExecuteEx(&sinfo);
        free(cmdLine);

        if (result) {
          WaitForSingleObject(sinfo.hProcess, INFINITE);
          CloseHandle(sinfo.hProcess);
        } else {
          WriteStatusFile(ELEVATION_CANCELED);
        }
      }

      if (argc > callbackIndex) {
        LaunchCallbackApp(argv[5], argc - callbackIndex,
                          argv + callbackIndex, sUsingService);
      }

      CloseHandle(elevatedFileHandle);

      if (!useService && !noServiceFallback &&
          INVALID_HANDLE_VALUE == updateLockFileHandle) {
        // We didn't use the service and we did run the elevated updater.exe.
        // The elevated updater.exe is responsible for writing out the
        // update.status file.
        return 0;
      } else if(useService) {
        // The service command was launched. The service is responsible for
        // writing out the update.status file.
        if (updateLockFileHandle != INVALID_HANDLE_VALUE) {
          CloseHandle(updateLockFileHandle);
        }
        return 0;
      } else {
        // Otherwise the service command was not launched at all.
        // We are only reaching this code path because we had write access
        // all along to the directory and a fallback key existed, and we
        // have fallback disabled (MOZ_NO_SERVICE_FALLBACK env var exists).
        // We only currently use this env var from XPCShell tests.
        CloseHandle(updateLockFileHandle);
        WriteStatusFile(lastFallbackError);
        return 0;
      }
    }
  }
#endif

#if defined(MOZ_WIDGET_GONK)
  // In gonk, the master b2g process sets its umask to 0027 because
  // there's no reason for it to ever create world-readable files.
  // The updater binary, however, needs to do this, and it inherits
  // the master process's cautious umask.  So we drop down a bit here.
  umask(0022);

  // Remount the /system partition as read-write for gonk. The destructor will
  // remount /system as read-only. We add an extra level of scope here to avoid
  // calling LogFinish() before the GonkAutoMounter destructor has a chance
  // to be called
  {
    GonkAutoMounter mounter;
    if (mounter.GetAccess() != MountAccess::ReadWrite) {
      WriteStatusFile(FILESYSTEM_MOUNT_READWRITE_ERROR);
      return 1;
    }
#endif

  if (sStagedUpdate) {
    // When staging updates, blow away the old installation directory and create
    // it from scratch.
    ensure_remove_recursive(gWorkingDirPath);
  }
  if (!sReplaceRequest) {
    // Change current directory to the directory where we need to apply the update.
    if (NS_tchdir(gWorkingDirPath) != 0) {
      // Try to create the destination directory if it doesn't exist
      int rv = NS_tmkdir(gWorkingDirPath, 0755);
      if (rv == OK && errno != EEXIST) {
        // Try changing the current directory again
        if (NS_tchdir(gWorkingDirPath) != 0) {
          // OK, time to give up!
          return 1;
        }
      } else {
        // Failed to create the directory, bail out
        return 1;
      }
    }
  }

#ifdef XP_WIN
  // For replace requests, we don't need to do any real updates, so this is not
  // necessary.
  if (!sReplaceRequest) {
    // Allocate enough space for the length of the path an optional additional
    // trailing slash and null termination.
    NS_tchar *destpath = (NS_tchar *) malloc((NS_tstrlen(gWorkingDirPath) + 2) * sizeof(NS_tchar));
    if (!destpath)
      return 1;

    NS_tchar *c = destpath;
    NS_tstrcpy(c, gWorkingDirPath);
    c += NS_tstrlen(gWorkingDirPath);
    if (gWorkingDirPath[NS_tstrlen(gWorkingDirPath) - 1] != NS_T('/') &&
        gWorkingDirPath[NS_tstrlen(gWorkingDirPath) - 1] != NS_T('\\')) {
      NS_tstrcat(c, NS_T("/"));
      c += NS_tstrlen(NS_T("/"));
    }
    *c = NS_T('\0');
    c++;

    gDestPath = destpath;
  }

  NS_tchar applyDirLongPath[MAXPATHLEN];
  if (!GetLongPathNameW(gWorkingDirPath, applyDirLongPath,
                        sizeof(applyDirLongPath)/sizeof(applyDirLongPath[0]))) {
    LOG(("CVE_2015_0833_VULN_NS_main: unable to find apply to dir: " LOG_S, gWorkingDirPath));
    LogFinish();
    WriteStatusFile(WRITE_ERROR);
    EXIT_WHEN_ELEVATED(elevatedLockFilePath, updateLockFileHandle, 1);
    if (argc > callbackIndex) {
      LaunchCallbackApp(argv[5], argc - callbackIndex,
                        argv + callbackIndex, sUsingService);
    }
    return 1;
  }

  HANDLE callbackFile = INVALID_HANDLE_VALUE;
  if (argc > callbackIndex) {
    // If the callback executable is specified it must exist for a successful
    // update.  It is important we null out the whole buffer here because later
    // we make the assumption that the callback application is inside the
    // apply-to dir.  If we don't have a fully null'ed out buffer it can lead
    // to stack corruption which causes crashes and other problems.
    NS_tchar callbackLongPath[MAXPATHLEN];
    ZeroMemory(callbackLongPath, sizeof(callbackLongPath));
    NS_tchar *targetPath = argv[callbackIndex];
    NS_tchar buffer[MAXPATHLEN * 2] = { NS_T('\0') };
    size_t bufferLeft = MAXPATHLEN * 2;
    if (sReplaceRequest) {
      // In case of replace requests, we should look for the callback file in
      // the destination directory.
      size_t commonPrefixLength = PathCommonPrefixW(argv[callbackIndex],
                                                    gInstallDirPath,
                                                    nullptr);
      NS_tchar *p = buffer;
      NS_tstrncpy(p, argv[callbackIndex], commonPrefixLength);
      p += commonPrefixLength;
      bufferLeft -= commonPrefixLength;
      NS_tstrncpy(p, gInstallDirPath + commonPrefixLength, bufferLeft);

      size_t len = NS_tstrlen(gInstallDirPath + commonPrefixLength);
      p += len;
      bufferLeft -= len;
      *p = NS_T('\\');
      ++p;
      bufferLeft--;
      *p = NS_T('\0');
      NS_tchar installDir[MAXPATHLEN];
      NS_tstrcpy(installDir, gInstallDirPath);
      size_t callbackPrefixLength = PathCommonPrefixW(argv[callbackIndex],
                                                      installDir,
                                                      nullptr);
      NS_tstrncpy(p, argv[callbackIndex] + std::max(callbackPrefixLength, commonPrefixLength), bufferLeft);
      targetPath = buffer;
    }
    if (!GetLongPathNameW(targetPath, callbackLongPath,
                          sizeof(callbackLongPath)/sizeof(callbackLongPath[0]))) {
      LOG(("CVE_2015_0833_VULN_NS_main: unable to find callback file: " LOG_S, targetPath));
      LogFinish();
      WriteStatusFile(WRITE_ERROR);
      EXIT_WHEN_ELEVATED(elevatedLockFilePath, updateLockFileHandle, 1);
      if (argc > callbackIndex) {
        LaunchCallbackApp(argv[5],
                          argc - callbackIndex,
                          argv + callbackIndex,
                          sUsingService);
      }
      return 1;
    }

    // Doing this is only necessary when we're actually applying a patch.
    if (!sReplaceRequest) {
      int len = NS_tstrlen(applyDirLongPath);
      NS_tchar *s = callbackLongPath;
      NS_tchar *d = gCallbackRelPath;
      // advance to the apply to directory and advance past the trailing backslash
      // if present.
      s += len;
      if (*s == NS_T('\\'))
        ++s;

      // Copy the string and replace backslashes with forward slashes along the
      // way.
      do {
        if (*s == NS_T('\\'))
          *d = NS_T('/');
        else
          *d = *s;
        ++s;
        ++d;
      } while (*s);
      *d = NS_T('\0');
      ++d;

      // Make a copy of the callback executable so it can be read when patching.
      NS_tsnprintf(gCallbackBackupPath,
                   sizeof(gCallbackBackupPath)/sizeof(gCallbackBackupPath[0]),
                   NS_T("%s" CALLBACK_BACKUP_EXT), argv[callbackIndex]);
      NS_tremove(gCallbackBackupPath);
      CopyFileW(argv[callbackIndex], gCallbackBackupPath, false);

      // Since the process may be signaled as exited by WaitForSingleObject before
      // the release of the executable image try to lock the main executable file
      // multiple times before giving up.  If we end up giving up, we won't
      // fail the update.
      const int max_retries = 10;
      int retries = 1;
      DWORD lastWriteError = 0;
      do {
        // By opening a file handle wihout FILE_SHARE_READ to the callback
        // executable, the OS will prevent launching the process while it is
        // being updated.
        callbackFile = CreateFileW(targetPath,
                                   DELETE | GENERIC_WRITE,
                                   // allow delete, rename, and write
                                   FILE_SHARE_DELETE | FILE_SHARE_WRITE,
                                   nullptr, OPEN_EXISTING, 0, nullptr);
        if (callbackFile != INVALID_HANDLE_VALUE)
          break;

        lastWriteError = GetLastError();
        LOG(("CVE_2015_0833_VULN_NS_main: callback app file open attempt %d failed. " \
             "File: " LOG_S ". Last error: %d", retries,
             targetPath, lastWriteError));

        Sleep(100);
      } while (++retries <= max_retries);

      // CreateFileW will fail if the callback executable is already in use.
      if (callbackFile == INVALID_HANDLE_VALUE) {
        // Only fail the update if the last error was not a sharing violation.
        if (lastWriteError != ERROR_SHARING_VIOLATION) {
          LOG(("CVE_2015_0833_VULN_NS_main: callback app file in use, failed to exclusively open " \
               "executable file: " LOG_S, argv[callbackIndex]));
          LogFinish();
          if (lastWriteError == ERROR_ACCESS_DENIED) {
            WriteStatusFile(WRITE_ERROR_ACCESS_DENIED);
          } else {
            WriteStatusFile(WRITE_ERROR_CALLBACK_APP);
          }

          NS_tremove(gCallbackBackupPath);
          EXIT_WHEN_ELEVATED(elevatedLockFilePath, updateLockFileHandle, 1);
          LaunchCallbackApp(argv[5],
                            argc - callbackIndex,
                            argv + callbackIndex,
                            sUsingService);
          return 1;
        }
        LOG(("CVE_2015_0833_VULN_NS_main: callback app file in use, continuing without " \
             "exclusive access for executable file: " LOG_S,
             argv[callbackIndex]));
      }
    }
  }

  // DELETE_DIR is not required when staging an update.
  if (!sStagedUpdate && !sReplaceRequest) {
    // The directory to move files that are in use to on Windows. This directory
    // will be deleted after the update is finished or on OS reboot using
    // MoveFileEx if it contains files that are in use.
    if (NS_taccess(DELETE_DIR, F_OK)) {
      NS_tmkdir(DELETE_DIR, 0755);
    }
  }
#endif /* XP_WIN */

  // Run update process on a background thread.  ShowProgressUI may return
  // before QuitProgressUI has been called, so wait for UpdateThreadFunc to
  // terminate.  Avoid showing the progress UI when staging an update.
  Thread t;
  if (t.Run(UpdateThreadFunc, nullptr) == 0) {
    if (!sStagedUpdate && !sReplaceRequest) {
      ShowProgressUI();
    }
  }
  t.Join();

#ifdef XP_WIN
  if (argc > callbackIndex && !sReplaceRequest) {
    if (callbackFile != INVALID_HANDLE_VALUE) {
      CloseHandle(callbackFile);
    }
    // Remove the copy of the callback executable.
    NS_tremove(gCallbackBackupPath);
  }

  if (!sStagedUpdate && !sReplaceRequest && _wrmdir(DELETE_DIR)) {
    LOG(("CVE_2015_0833_VULN_NS_main: unable to remove directory: " LOG_S ", err: %d",
         DELETE_DIR, errno));
    // The directory probably couldn't be removed due to it containing files
    // that are in use and will be removed on OS reboot. The call to remove the
    // directory on OS reboot is done after the calls to remove the files so the
    // files are removed first on OS reboot since the directory must be empty
    // for the directory removal to be successful. The MoveFileEx call to remove
    // the directory on OS reboot will fail if the process doesn't have write
    // access to the HKEY_LOCAL_MACHINE registry key but this is ok since the
    // installer / uninstaller will delete the directory along with its contents
    // after an update is applied, on reinstall, and on uninstall.
    if (MoveFileEx(DELETE_DIR, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT)) {
      LOG(("CVE_2015_0833_VULN_NS_main: directory will be removed on OS reboot: " LOG_S,
           DELETE_DIR));
    } else {
      LOG(("CVE_2015_0833_VULN_NS_main: failed to schedule OS reboot removal of " \
           "directory: " LOG_S, DELETE_DIR));
    }
  }
#endif /* XP_WIN */

#if defined(MOZ_WIDGET_GONK)
  } // end the extra level of scope for the GonkAutoMounter
#endif

#ifdef XP_MACOSX
  // When the update is successful remove the precomplete file in the root of
  // the application bundle and move the distribution directory from
  // Contents/MacOS to Contents/Resources and if both exist delete the
  // directory under Contents/MacOS (see Bug 1068439).
  if (gSucceeded && !sStagedUpdate) {
    NS_tchar oldPrecomplete[MAXPATHLEN];
    NS_tsnprintf(oldPrecomplete, sizeof(oldPrecomplete)/sizeof(oldPrecomplete[0]),
                 NS_T("%s/precomplete"), gInstallDirPath);
    NS_tremove(oldPrecomplete);

    NS_tchar oldDistDir[MAXPATHLEN];
    NS_tsnprintf(oldDistDir, sizeof(oldDistDir)/sizeof(oldDistDir[0]),
                 NS_T("%s/Contents/MacOS/distribution"), gInstallDirPath);
    int rv = NS_taccess(oldDistDir, F_OK);
    if (!rv) {
      NS_tchar newDistDir[MAXPATHLEN];
      NS_tsnprintf(newDistDir, sizeof(newDistDir)/sizeof(newDistDir[0]),
                   NS_T("%s/Contents/Resources/distribution"), gInstallDirPath);
      rv = NS_taccess(newDistDir, F_OK);
      if (!rv) {
        LOG(("New distribution directory already exists... removing old " \
             "distribution directory: " LOG_S, oldDistDir));
        rv = ensure_remove_recursive(oldDistDir);
        if (rv) {
          LOG(("Removing old distribution directory failed - err: %d", rv));
        }
      } else {
        LOG(("Moving old distribution directory to new location. src: " LOG_S \
             ", dst:" LOG_S, oldDistDir, newDistDir));
        rv = rename_file(oldDistDir, newDistDir, true);
        if (rv) {
          LOG(("Moving old distribution directory to new location failed - " \
               "err: %d", rv));
        }
      }
    }
  }
#endif /* XP_MACOSX */

  LogFinish();

  if (argc > callbackIndex) {
#if defined(XP_WIN)
    if (gSucceeded) {
      // The service update will only be executed if it is already installed.
      // For first time installs of the service, the install will happen from
      // the PostUpdate process. We do the service update process here
      // because it's possible we are updating with updater.exe without the
      // service if the service failed to apply the update. We want to update
      // the service to a newer version in that case. If we are not running
      // through the service, then MOZ_USING_SERVICE will not exist.
      if (!sUsingService) {
        if (!LaunchWinPostProcess(gInstallDirPath, gPatchDirPath, false, nullptr)) {
          LOG(("CVE_2015_0833_VULN_NS_main: The post update process could not be launched."));
        }

        StartServiceUpdate(gInstallDirPath);
      }
    }
    EXIT_WHEN_ELEVATED(elevatedLockFilePath, updateLockFileHandle, 0);
#endif /* XP_WIN */
#ifdef XP_MACOSX
    if (gSucceeded) {
      LaunchMacPostProcess(gInstallDirPath);
    }
#endif /* XP_MACOSX */

    if (getenv("MOZ_PROCESS_UPDATES") == nullptr) {
      LaunchCallbackApp(argv[5],
                        argc - callbackIndex,
                        argv + callbackIndex,
                        sUsingService);
    }
  }

  return gSucceeded ? 0 : 1;
}
