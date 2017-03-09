program Packer;

uses
  Forms,
  maincode in 'maincode.pas' {Form1};

{$R *.res}

begin
  Application.Initialize;
  Application.Title:='AHPacker';
  Application.CreateForm(TForm1, Form1);
  Application.Run;
end.
