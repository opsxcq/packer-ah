object Form1: TForm1
  Left = 220
  Top = 135
  BorderIcons = [biSystemMenu, biMinimize]
  BorderStyle = bsSingle
  Caption = 'AHPacker v0.1 by FEUERRADER [AHTeam]'
  ClientHeight = 298
  ClientWidth = 542
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -14
  Font.Name = 'MS Sans Serif'
  Font.Style = []
  Icon.Data = {
    0000010001002020100000000000E80200001600000028000000200000004000
    0000010004000000000080020000000000000000000000000000000000000000
    0000000080000080000000808000800000008000800080800000C0C0C0008080
    80000000FF0000FF000000FFFF00FF000000FF00FF00FFFF0000FFFFFF00CCC0
    000CCCC0000000000CCCC7777CCCCCCC0000CCCC00000000CCCC7777CCCCCCCC
    C0000CCCCCCCCCCCCCC7777CCCCC0CCCCC0000CCCCCCCCCCCC7777CCCCC700CC
    C00CCCC0000000000CCCC77CCC77000C0000CCCC00000000CCCC7777C7770000
    00000CCCC000000CCCC777777777C000C00000CCCC0000CCCC77777C777CCC00
    CC00000CCCCCCCCCC77777CC77CCCCC0CCC000CCCCC00CCCCC777CCC7CCCCCCC
    CCCC0CCCCCCCCCCCCCC7CCCCCCCCCCCC0CCCCCCCCCCCCCCCCCCCCCC7CCC70CCC
    00CCCCCCCC0CC0CCCCCCCC77CC7700CC000CCCCCC000000CCCCCC777CC7700CC
    0000CCCC00000000CCCC7777CC7700CC0000C0CCC000000CCC7C7777CC7700CC
    0000C0CCC000000CCC7C7777CC7700CC0000CCCC00000000CCCC7777CC7700CC
    000CCCCCC000000CCCCCC777CC7700CC00CCCCCCCC0CC0CCCCCCCC77CC770CCC
    0CCCCCCCCCCCCCCCCCCCCCC7CCC7CCCCCCCC0CCCCCCCCCCCCCC7CCCCCCCCCCC0
    CCC000CCCCC00CCCCC777CCC7CCCCC00CC00000CCCCCCCCCC77777CC77CCC000
    C00000CCCC0000CCCC77777C777C000000000CCCC000000CCCC777777777000C
    0000CCCC00000000CCCC7777C77700CCC00CCCC0000000000CCCC77CCC770CCC
    CC0000CCCCCCCCCCCC7777CCCCC7CCCCC0000CCCCCCCCCCCCCC7777CCCCCCCCC
    0000CCCC00000000CCCC7777CCCCCCC0000CCCC0000000000CCCC7777CCC0000
    0000000000000000000000000000000000000000000000000000000000000000
    0000000000000000000000000000000000000000000000000000000000000000
    0000000000000000000000000000000000000000000000000000000000000000
    000000000000000000000000000000000000000000000000000000000000}
  OldCreateOrder = False
  Position = poScreenCenter
  OnCreate = FormCreate
  PixelsPerInch = 120
  TextHeight = 16
  object StatusBar1: TStatusBar
    Left = 0
    Top = 279
    Width = 542
    Height = 19
    Panels = <
      item
        Text = 'Ready'
        Width = 150
      end
      item
        Alignment = taCenter
        Text = 'Clock'
        Width = 70
      end
      item
        Width = 50
      end>
  end
  object pb: TProgressBar
    Left = 222
    Top = 281
    Width = 320
    Height = 17
    TabOrder = 0
  end
  object GroupBox1: TGroupBox
    Left = 8
    Top = 8
    Width = 529
    Height = 65
    Caption = ' File '
    TabOrder = 2
    object fileedit: TEdit
      Left = 16
      Top = 24
      Width = 464
      Height = 25
      ReadOnly = True
      TabOrder = 0
    end
    object XPButton1: TButton
      Left = 488
      Top = 24
      Width = 33
      Height = 24
      Caption = '...'
      TabOrder = 1
      OnClick = XPButton1Click
    end
  end
  object GroupBox2: TGroupBox
    Left = 8
    Top = 80
    Width = 529
    Height = 161
    Caption = ' Information '
    TabOrder = 3
    object log: TMemo
      Left = 8
      Top = 24
      Width = 513
      Height = 129
      Font.Charset = RUSSIAN_CHARSET
      Font.Color = 13652736
      Font.Height = -13
      Font.Name = 'MS Sans Serif'
      Font.Style = []
      Lines.Strings = (
        'Select a file...')
      ParentFont = False
      ReadOnly = True
      TabOrder = 0
    end
  end
  object packbutton: TButton
    Left = 400
    Top = 248
    Width = 137
    Height = 25
    Caption = 'Pack'
    TabOrder = 4
    OnClick = packbuttonClick
  end
  object aPLib: TaPLib
    Left = 48
    Top = 152
  end
  object OpenFiler: TOpenDialog
    DefaultExt = '*.exe'
    Filter = 'EXE Files|*.exe'
    Left = 80
    Top = 152
  end
  object clocks: TTimer
    Interval = 10
    OnTimer = clocksTimer
    Left = 112
    Top = 152
  end
end
