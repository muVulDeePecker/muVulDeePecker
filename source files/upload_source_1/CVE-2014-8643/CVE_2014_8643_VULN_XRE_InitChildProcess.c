nsresult
CVE_2014_8643_VULN_XRE_InitChildProcess(int aArgc,
                     char* aArgv[])
{
  NS_ENSURE_ARG_MIN(aArgc, 2);
  NS_ENSURE_ARG_POINTER(aArgv);
  NS_ENSURE_ARG_POINTER(aArgv[0]);

#if defined(XP_WIN)
  // From the --attach-console support in nsNativeAppSupportWin.cpp, but
  // here we are a content child process, so we always attempt to attach
  // to the parent's (ie, the browser's) console.
  // Try to attach console to the parent process.
  // It will succeed when the parent process is a command line,
  // so that stdio will be displayed in it.
  if (AttachConsole(ATTACH_PARENT_PROCESS)) {
    // Change std handles to refer to new console handles.
    // Before doing so, ensure that stdout/stderr haven't been
    // redirected to a valid file
    if (_fileno(stdout) == -1 ||
        _get_osfhandle(fileno(stdout)) == -1)
        freopen("CONOUT$", "w", stdout);
    // Merge stderr into CONOUT$ since there isn't any `CONERR$`.
    // http://msdn.microsoft.com/en-us/library/windows/desktop/ms683231%28v=vs.85%29.aspx
    if (_fileno(stderr) == -1 ||
        _get_osfhandle(fileno(stderr)) == -1)
        freopen("CONOUT$", "w", stderr);
    if (_fileno(stdin) == -1 || _get_osfhandle(fileno(stdin)) == -1)
        freopen("CONIN$", "r", stdin);
  }
#endif

  char aLocal;
  profiler_init(&aLocal);

  PROFILER_LABEL("Startup", "CVE_2014_8643_VULN_XRE_InitChildProcess",
    js::ProfileEntry::Category::OTHER);

  // Complete 'task_t' exchange for Mac OS X. This structure has the same size
  // regardless of architecture so we don't have any cross-arch issues here.
#ifdef XP_MACOSX
  if (aArgc < 1)
    return NS_ERROR_FAILURE;
  const char* const mach_port_name = aArgv[--aArgc];

  const int kTimeoutMs = 1000;

  MachSendMessage child_message(0);
  if (!child_message.AddDescriptor(MachMsgPortDescriptor(mach_task_self()))) {
    NS_WARNING("child AddDescriptor(mach_task_self()) failed.");
    return NS_ERROR_FAILURE;
  }

  ReceivePort child_recv_port;
  mach_port_t raw_child_recv_port = child_recv_port.GetPort();
  if (!child_message.AddDescriptor(MachMsgPortDescriptor(raw_child_recv_port))) {
    NS_WARNING("Adding descriptor to message failed");
    return NS_ERROR_FAILURE;
  }

  MachPortSender child_sender(mach_port_name);
  kern_return_t err = child_sender.SendMessage(child_message, kTimeoutMs);
  if (err != KERN_SUCCESS) {
    NS_WARNING("child SendMessage() failed");
    return NS_ERROR_FAILURE;
  }

  MachReceiveMessage parent_message;
  err = child_recv_port.WaitForMessage(&parent_message, kTimeoutMs);
  if (err != KERN_SUCCESS) {
    NS_WARNING("child WaitForMessage() failed");
    return NS_ERROR_FAILURE;
  }

  if (parent_message.GetTranslatedPort(0) == MACH_PORT_NULL) {
    NS_WARNING("child GetTranslatedPort(0) failed");
    return NS_ERROR_FAILURE;
  }
  err = task_set_bootstrap_port(mach_task_self(),
                                parent_message.GetTranslatedPort(0));
  if (err != KERN_SUCCESS) {
    NS_WARNING("child task_set_bootstrap_port() failed");
    return NS_ERROR_FAILURE;
  }
#endif

  SetupErrorHandling(aArgv[0]);  

#if defined(MOZ_CRASHREPORTER)
  if (aArgc < 1)
    return NS_ERROR_FAILURE;
  const char* const crashReporterArg = aArgv[--aArgc];
  
#  if defined(XP_WIN) || defined(XP_MACOSX)
  // on windows and mac, |crashReporterArg| is the named pipe on which the
  // server is listening for requests, or "-" if crash reporting is
  // disabled.
  if (0 != strcmp("-", crashReporterArg) && 
      !XRE_SetRemoteExceptionHandler(crashReporterArg)) {
    // Bug 684322 will add better visibility into this condition
    NS_WARNING("Could not setup crash reporting\n");
  }
#  elif defined(OS_LINUX)
  // on POSIX, |crashReporterArg| is "true" if crash reporting is
  // enabled, false otherwise
  if (0 != strcmp("false", crashReporterArg) && 
      !XRE_SetRemoteExceptionHandler(nullptr)) {
    // Bug 684322 will add better visibility into this condition
    NS_WARNING("Could not setup crash reporting\n");
  }
#  else
#    error "OOP crash reporting unsupported on this platform"
#  endif   
#endif // if defined(MOZ_CRASHREPORTER)

  gArgv = aArgv;
  gArgc = aArgc;

#if defined(MOZ_WIDGET_GTK)
  g_thread_init(nullptr);
#endif

#if defined(MOZ_WIDGET_QT)
  nsQAppInstance::AddRef();
#endif

  if (PR_GetEnv("MOZ_DEBUG_CHILD_PROCESS")) {
#ifdef OS_POSIX
      printf("\n\nCHILDCHILDCHILDCHILD\n  debug me @ %d\n\n", getpid());
      sleep(30);
#elif defined(OS_WIN)
      // Windows has a decent JIT debugging story, so NS_DebugBreak does the
      // right thing.
      NS_DebugBreak(NS_DEBUG_BREAK,
                    "Invoking NS_DebugBreak() to debug child process",
                    nullptr, __FILE__, __LINE__);
#endif
  }

  // child processes launched by GeckoChildProcessHost get this magic
  // argument appended to their command lines
  const char* const parentPIDString = aArgv[aArgc-1];
  NS_ABORT_IF_FALSE(parentPIDString, "NULL parent PID");
  --aArgc;

  char* end = 0;
  base::ProcessId parentPID = strtol(parentPIDString, &end, 10);
  NS_ABORT_IF_FALSE(!*end, "invalid parent PID");

  base::ProcessHandle parentHandle;
  mozilla::DebugOnly<bool> ok = base::OpenProcessHandle(parentPID, &parentHandle);
  NS_ABORT_IF_FALSE(ok, "can't open handle to parent");

#if defined(XP_WIN)
  // On Win7+, register the application user model id passed in by
  // parent. This insures windows created by the container properly
  // group with the parent app on the Win7 taskbar.
  const char* const appModelUserId = aArgv[--aArgc];
  if (appModelUserId) {
    // '-' implies no support
    if (*appModelUserId != '-') {
      nsString appId;
      appId.AssignWithConversion(nsDependentCString(appModelUserId));
      // The version string is encased in quotes
      appId.Trim(NS_LITERAL_CSTRING("\"").get());
      // Set the id
      SetTaskbarGroupId(appId);
    }
  }
#endif

  base::AtExitManager exitManager;
  NotificationService notificationService;

  NS_LogInit();

  nsresult rv = XRE_InitCommandLine(aArgc, aArgv);
  if (NS_FAILED(rv)) {
    profiler_shutdown();
    NS_LogTerm();
    return NS_ERROR_FAILURE;
  }

  MessageLoop::Type uiLoopType;
  switch (XRE_GetProcessType()) {
  case GeckoProcessType_Content:
      // Content processes need the XPCOM/chromium frankenventloop
      uiLoopType = MessageLoop::TYPE_MOZILLA_CHILD;
      break;
  default:
      uiLoopType = MessageLoop::TYPE_UI;
      break;
  }

  {
    // This is a lexical scope for the MessageLoop below.  We want it
    // to go out of scope before NS_LogTerm() so that we don't get
    // spurious warnings about XPCOM objects being destroyed from a
    // static context.

    // Associate this thread with a UI MessageLoop
    MessageLoop uiMessageLoop(uiLoopType);
    {
      nsAutoPtr<ProcessChild> process;

#ifdef XP_WIN
      mozilla::ipc::windows::InitUIThread();
#endif

      switch (XRE_GetProcessType()) {
      case GeckoProcessType_Default:
        NS_RUNTIMEABORT("This makes no sense");
        break;

      case GeckoProcessType_Plugin:
        process = new PluginProcessChild(parentHandle);
        break;

      case GeckoProcessType_Content: {
          process = new ContentProcess(parentHandle);
          // If passed in grab the application path for xpcom init
          nsCString appDir;
          for (int idx = aArgc; idx > 0; idx--) {
            if (aArgv[idx] && !strcmp(aArgv[idx], "-appdir")) {
              appDir.Assign(nsDependentCString(aArgv[idx+1]));
              static_cast<ContentProcess*>(process.get())->SetAppDir(appDir);
              break;
            }
          }
        }
        break;

      case GeckoProcessType_IPDLUnitTest:
#ifdef MOZ_IPDL_TESTS
        process = new IPDLUnitTestProcessChild(parentHandle);
#else 
        NS_RUNTIMEABORT("rebuild with --enable-ipdl-tests");
#endif
        break;

      case GeckoProcessType_GMPlugin:
        process = new gmp::GMPProcessChild(parentHandle);
        break;

      default:
        NS_RUNTIMEABORT("Unknown main thread class");
      }

      if (!process->Init()) {
        profiler_shutdown();
        NS_LogTerm();
        return NS_ERROR_FAILURE;
      }

      // Run the UI event loop on the main thread.
      uiMessageLoop.MessageLoop::Run();

      // Allow ProcessChild to clean up after itself before going out of
      // scope and being deleted
      process->CleanUp();
      mozilla::Omnijar::CleanUp();
    }
  }

  profiler_shutdown();
  NS_LogTerm();
  return XRE_DeinitCommandLine();
}
