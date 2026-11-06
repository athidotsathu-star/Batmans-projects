; Inno Setup 6 installer definition for Windows.
#define MyAppName "Batman Bug Hunter X"
#define MyAppVersion "3.0.0"
#define MyAppPublisher "Batcomputer"
#define MyAppExeName "BatmanBugHunter.exe"

[Setup]
AppId={{B7C69A8A-27A2-4F21-A9A7-8E41E1A4B310}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={localappdata}\Programs\Batman Bug Hunter X
DefaultGroupName={#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExeName}
OutputDir=installer
OutputBaseFilename=BatmanBugHunter-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=lowest
SetupLogging=yes
CloseApplications=yes

[Files]
Source: "dist\BatmanBugHunter\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "dist\BatmanBugHunterUpdater.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Batman Bug Hunter X"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Batman Bug Hunter X (Browser)"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--browser"
Name: "{group}\Batman Bug Hunter X Updater"; Filename: "{app}\BatmanBugHunterUpdater.exe"
Name: "{autodesktop}\Batman Bug Hunter X"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch Batman Bug Hunter X"; Flags: nowait postinstall skipifsilent
