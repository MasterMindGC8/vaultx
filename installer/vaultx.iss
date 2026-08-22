; Vault X Windows installer.
;
; Fixed AppId so re-running a newer-version installer upgrades in place
; (same install directory, same Start Menu entry, old files cleanly
; replaced) instead of creating a second, parallel install. This is what
; makes the "one-click update" flow in the app (see
; lib/services/update_checker.dart) actually work: it just downloads and
; silently re-runs this installer.
#define MyAppId "{{A7C93F1E-2B4D-4E11-9C2A-8F1D6E4B7A31}"
#define MyAppName "Vault X"
#define MyAppVersion "1.1.1"
#define MyAppPublisher "Vault X Project"
#define MyAppExeName "client_app.exe"
#define ReleaseDir "..\client_app\build\windows\x64\runner\Release"

[Setup]
AppId={#MyAppId}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=..\dist
OutputBaseFilename=VaultXSetup-{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#MyAppExeName}
; Silent-update runs (see UpdateChecker) pass /VERYSILENT themselves; this
; default just governs a normal double-click install.
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Files]
Source: "{#ReleaseDir}\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#ReleaseDir}\crypto_core.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#ReleaseDir}\flutter_windows.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#ReleaseDir}\native_assets.yaml"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "{#ReleaseDir}\data\*"; DestDir: "{app}\data"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "vc_redist.x64.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{tmp}\vc_redist.x64.exe"; Parameters: "/install /quiet /norestart"; StatusMsg: "Installing required Microsoft Visual C++ Runtime..."; Check: VCRedistNeedsInstall
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent

[Code]
function VCRedistNeedsInstall: Boolean;
var
  Version: String;
begin
  // Same check the app's own launcher used to do by hand: only run the
  // (larger, slower) redistributable installer if it isn't already there.
  Result := not RegQueryStringValue(HKLM64, 'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64', 'Version', Version);
end;
