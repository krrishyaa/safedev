; Inno Setup Script for SafeDev
; Builds a Windows installer for the PyInstaller output.

#define MyAppName "SafeDev"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "SafeDev Sentinel"
#define MyAppURL "https://github.com/krrishyaa/safedev"
#define MyAppExeName "safedev.exe"
#define MyAppDistDir "dist\safedev"
#define MyInstallerBaseName "SafeDev-Setup-" + MyAppVersion

[Setup]
AppId={{B8E9F2A3-4C6D-4E5F-A6B7-C8D9E0F1A2B3}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
OutputDir=dist
OutputBaseFilename={#MyInstallerBaseName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64
ChangesEnvironment=yes
DisableDirPage=no
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "addtopath"; Description: "Add SafeDev to PATH"; GroupDescription: "System Integration:"; Flags: unchecked

[Files]
Source: "{#MyAppDistDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "requirements.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch SafeDev"; Flags: nowait postinstall skipifsilent

[Code]
const
  EnvironmentKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment';

function AddPathEntry(PathValue, NewEntry: string): string;
var
  NormalizedPath: string;
  NormalizedEntry: string;
begin
  NormalizedPath := ';' + Lowercase(PathValue) + ';';
  NormalizedEntry := ';' + Lowercase(NewEntry) + ';';

  if Pos(NormalizedEntry, NormalizedPath) > 0 then
    Result := PathValue
  else if PathValue = '' then
    Result := NewEntry
  else if PathValue[Length(PathValue)] = ';' then
    Result := PathValue + NewEntry
  else
    Result := PathValue + ';' + NewEntry;
end;

function RemovePathEntry(PathValue, EntryToRemove: string): string;
var
  I, StartIdx, EndIdx: Integer;
  CurrentPart: string;
begin
  Result := '';
  I := 1;
  while I <= Length(PathValue) do
  begin
    StartIdx := I;
    while (I <= Length(PathValue)) and (PathValue[I] <> ';') do Inc(I);
    EndIdx := I - 1;
    if StartIdx <= EndIdx then
    begin
      CurrentPart := Trim(Copy(PathValue, StartIdx, EndIdx - StartIdx + 1));
      if (CurrentPart <> '') and (CompareText(CurrentPart, EntryToRemove) <> 0) then
      begin
        if Result = '' then
          Result := CurrentPart
        else
          Result := Result + ';' + CurrentPart;
      end;
    end;
    if (I <= Length(PathValue)) and (PathValue[I] = ';') then Inc(I);
  end;
end;

procedure UpdatePathForCurrentInstall(AddEntry: Boolean);
var
  ExistingPath: string;
  UpdatedPath: string;
begin
  if not RegQueryStringValue(HKLM, EnvironmentKey, 'Path', ExistingPath) then
    ExistingPath := '';

  if AddEntry then
    UpdatedPath := AddPathEntry(ExistingPath, ExpandConstant('{app}'))
  else
    UpdatedPath := RemovePathEntry(ExistingPath, ExpandConstant('{app}'));

  if UpdatedPath <> ExistingPath then
    RegWriteExpandStringValue(HKLM, EnvironmentKey, 'Path', UpdatedPath);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and WizardIsTaskSelected('addtopath') then
    UpdatePathForCurrentInstall(True);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    UpdatePathForCurrentInstall(False);
end;
