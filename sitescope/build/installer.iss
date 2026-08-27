; ===================================================================
;  SiteScope Windows installer (Inno Setup 6)
;
;  Compile with:  ISCC.exe build\installer.iss
;  Expects dist\SiteScope.exe to already exist (run build.bat first).
;
;  Installs per-user by default so no administrator rights are needed -
;  important for the target audience, who often use a standard account
;  on a machine they do not administer.
; ===================================================================

#define AppName        "SiteScope"
#define AppVersion     "1.0.0"
#define AppPublisher   "SEDE Studios - UTS Cybersecurity Capstone"
#define AppExeName     "SiteScope.exe"

[Setup]
AppId={{8C4E6A21-9D3F-4B77-A1C6-5E2F8B90D437}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
DisableDirPage=no
LicenseFile=..\LICENSE
OutputDir=..\dist
OutputBaseFilename=SiteScope-Setup
SetupIconFile=sitescope.ico
UninstallDisplayIcon={app}\{#AppExeName}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; Per-user install: no UAC prompt, works on a locked-down machine.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
AppPublisherURL=https://github.com/
AppSupportURL=https://github.com/
AppUpdatesURL=https://github.com/

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; \
    GroupDescription: "Additional shortcuts:"

[Files]
Source: "..\dist\SiteScope.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md";          DestDir: "{app}"; Flags: ignoreversion isreadme
Source: "..\LICENSE";            DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}";                 Filename: "{app}\{#AppExeName}"
Name: "{group}\Uninstall {#AppName}";       Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}";           Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExeName}"; \
    Description: "Start {#AppName} now"; \
    Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Leave the user's scan history and reports in %LOCALAPPDATA%\SiteScope alone.
; Removing someone's security records without asking would be the wrong default;
; the folder path is shown in the app under Settings so it can be deleted by hand.
Type: dirifempty; Name: "{app}"

[Code]
function InitializeSetup(): Boolean;
begin
  Result := True;
end;
