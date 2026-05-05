#define MyAppName "VulnScan Pro"
#define MyAppVersion "1.0"
#define MyAppPublisher "Hawkz"
#define MyAppExeName "vulnscan-pro.exe"

[Setup]
AppId={{B4F2A1C3-8E7D-4F2A-9B1C-3D5E7F8A9B2C}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\VulnScan Pro
DefaultGroupName={#MyAppName}
OutputDir=C:\Users\Dylan\vulnscan-pro\installer\output
OutputBaseFilename=VulnScanPro_Setup_v1.0
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
UninstallDisplayIcon={app}\vulnscan-pro.exe

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "addtopath"; Description: "Ajouter VulnScan Pro au PATH (recommande)"; GroupDescription: "Options:"

[Files]
Source: "C:\Users\Dylan\vulnscan-pro\dist\vulnscan-pro.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "C:\Users\Dylan\vulnscan-pro\installer\nmap-7.95-setup.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall

[Icons]
Name: "{group}\VulnScan Pro"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Desinstaller VulnScan Pro"; Filename: "{uninstallexe}"

[Registry]
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Check: NeedsAddPath(ExpandConstant('{app}')); Tasks: addtopath

[Run]
Filename: "{tmp}\nmap-7.95-setup.exe"; Parameters: "/S"; StatusMsg: "Installation de Nmap..."; Flags: waituntilterminated

[Code]
function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE, 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'Path', OrigPath) then begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Param + ';', ';' + OrigPath + ';') = 0;
end;
