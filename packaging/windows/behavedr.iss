; Inno Setup script — Behavedr Windows installer
; Build: iscc packaging\windows\behavedr.iss /DMyAppVersion=0.0.4 /DPublishDir=...\publish\agent-win-x64

#ifndef MyAppVersion
  #define MyAppVersion "0.0.4"
#endif
#ifndef PublishDir
  #define PublishDir "..\..\publish\agent-win-x64"
#endif
#ifndef OutputDir
  #define OutputDir "..\..\dist\windows"
#endif

#define MyAppName "Behavedr"
#define MyAppPublisher "CroatiaSecurity"
#define MyAppURL "https://github.com/CroatiaSecurity/Behavedr"
#define MyAppExeName "Behavedr.exe"
#define MyServiceName "Behavedr"

[Setup]
AppId={{A7C4E8F1-2B3D-4E5F-9A0B-1C2D3E4F5A6B}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}/releases
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
LicenseFile=
InfoBeforeFile=
OutputDir={#OutputDir}
OutputBaseFilename=Behavedr-Setup-{#MyAppVersion}-win-x64
SetupIconFile={#PublishDir}\Assets\Behavedr.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#MyAppExeName}
VersionInfoVersion={#MyAppVersion}.0
VersionInfoCompany={#MyAppPublisher}
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"; Flags: unchecked
Name: "startmenu"; Description: "Create a &Start Menu shortcut"; GroupDescription: "Additional icons:"; Flags: checkedonce
Name: "installservice"; Description: "Install as Windows &Service (auto-start)"; GroupDescription: "Service:"; Flags: checkedonce

[Files]
; Single-file publish: Behavedr.exe (+ optional Assets + config)
Source: "{#PublishDir}\Behavedr.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PublishDir}\appsettings.json"; DestDir: "{app}"; Flags: ignoreversion onlyifdoesntexist skipifsourcedoesntexist
Source: "{#PublishDir}\Assets\*"; DestDir: "{app}\Assets"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist
Source: "{#PublishDir}\README.txt"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist

[Dirs]
; Restrict install directory: only SYSTEM and Administrators can write
Name: "{app}"; Permissions: admins-full system-full users-readexec
; Logs directory: agent writes here
Name: "{app}\logs"; Permissions: admins-full system-full users-readexec
; Quarantine directory
Name: "{app}\quarantine"; Permissions: admins-full system-full
; Buffer directory for offline reports
Name: "{app}\buffer"; Permissions: admins-full system-full

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: startmenu
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"; Tasks: startmenu
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; Register and start the Windows Service if user selected that task
Filename: "sc.exe"; Parameters: "create {#MyServiceName} binPath=""{app}\{#MyAppExeName}"" start=auto DisplayName=""{#MyAppName} Agent"""; Flags: runhidden waituntilterminated; Tasks: installservice
Filename: "sc.exe"; Parameters: "description {#MyServiceName} ""Behavedr behavioral EDR agent — real-time endpoint monitoring"""; Flags: runhidden waituntilterminated; Tasks: installservice
Filename: "sc.exe"; Parameters: "failure {#MyServiceName} reset=86400 actions=restart/5000/restart/10000/restart/30000"; Flags: runhidden waituntilterminated; Tasks: installservice
Filename: "sc.exe"; Parameters: "start {#MyServiceName}"; Flags: runhidden waituntilterminated; Tasks: installservice
; If not installing as service, offer to launch manually
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent; Tasks: not installservice

[UninstallRun]
; Stop and remove the service on uninstall
Filename: "sc.exe"; Parameters: "stop {#MyServiceName}"; Flags: runhidden waituntilterminated
Filename: "sc.exe"; Parameters: "delete {#MyServiceName}"; Flags: runhidden waituntilterminated

[UninstallDelete]
Type: filesandordirs; Name: "{app}\logs"
Type: filesandordirs; Name: "{app}\buffer"
Type: filesandordirs; Name: "{app}"
