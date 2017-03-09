/// Very simple packer
/// Uses APLib 0.42
/// Packs only section #1
//////////////////////////////////////////////
/// Thanks: -=ALEX=- [KpTeam], vins, MC707 ///
//////////////////////////////////////////////
/// Author: FEUERRADER [AHTeam]            ///
//////////////////////////////////////////////
/// Use parts of code with mention of my name!
//////////////////////////////////////////////
unit maincode;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, aPLib, StdCtrls, ComCtrls, PE_Files, Menus, ExtCtrls, shellapi;

type
  TForm1 = class(TForm)
    aPLib: TaPLib;
    pb: TProgressBar;
    OpenFiler: TOpenDialog;
    StatusBar1: TStatusBar;
    clocks: TTimer;
    GroupBox1: TGroupBox;
    fileedit: TEdit;
    XPButton1: TButton;
    GroupBox2: TGroupBox;
    log: TMemo;
    packbutton: TButton;
    procedure AddLog(text:string);
    procedure ClearLog;
    procedure XPButton1Click(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure clocksTimer(Sender: TObject);
    procedure packbuttonClick(Sender: TObject);
  private
  public
    CurFileSz : DWORD;
  end;

  (*$IFDEF DYNAMIC_VERSION*)
  function CallBack(w0, w1, w2 : DWORD; cbparam : Pointer) : DWORD;stdcall;
(*$ELSE*)
  function CallBack(w0, w1, w2 : DWORD; cbparam : Pointer) : DWORD;cdecl;
(*$ENDIF*)

var
  Form1: TForm1;

const
  packer_ver:string='AHPacker v0.1 by FEUERRADER [AHTeam]';
  
implementation

{$R *.dfm}
{$R windowsxp.res}

TYPE
IMAGE_DIR_ITEM=record
                 VirtualAddress:DWORD;
                 Size:DWORD;
               end;

IMAGE_FILE_HEADER=record
                         Machine:WORD;
                         NumberOfSections:WORD;
                         TimeDateStamp:DWORD;
                         PointerToSymbolTable:DWORD;
                         NumberOfSymbols:DWORD;
                         SizeOfOptionalHeader:WORD;
                         Characteristics:WORD;
                  end;

IMAGE_OPTIONAL_HEADER=record
                             Magic:WORD;
                             MajorLinkerVersion:BYTE;
                             MinorLinkerVersion:BYTE;
                             SizeOfCode:DWORD;
                             SizeOfInitializedData:DWORD;
                             SizeOfUninitializedData:DWORD;
                             AddressOfEntryPoint:DWORD;
                             BaseOfCode:DWORD;
                             BaseOfData:DWORD;
                             ImageBase:DWORD;
                             SectionAlignment:DWORD;
                             FileAlignment:DWORD;
                             MajorOperatingSystemVersion:WORD;
                             MinorOperatingSystemVersion:WORD;
                             MajorImageVersion:WORD;
                             MinorImageVersion:WORD;
                             MajorSubsystemVersion:WORD;
                             MinorSubsystemVersion:WORD;
                             Win32VersionValue:DWORD;
                             SizeOfImage:DWORD;
                             SizeOfHeaders:DWORD;
                             CheckSum:DWORD;
                             Subsystem:WORD;
                             DllCharacteristics:WORD;
                             SizeOfStackReserve:DWORD;
                             SizeOfStackCommit:DWORD;
                             SizeOfHeapReserve:DWORD;
                             SizeOfHeapCommit:DWORD;
                             LoaderFlags:DWORD;
                             NumberOfRvaAndSizes:DWORD;
                             IMAGE_DIRECTORY_ENTRIES:record
                                                    _EXPORT:IMAGE_DIR_ITEM;
                                                    IMPORT:IMAGE_DIR_ITEM;
                                                    RESOURCE:IMAGE_DIR_ITEM;
                                                    EXCEPTION:IMAGE_DIR_ITEM;
                                                    SECURITY:IMAGE_DIR_ITEM;
                                                    BASERELOC:IMAGE_DIR_ITEM;
                                                    DEBUG:IMAGE_DIR_ITEM;
                                                    COPYRIGHT:IMAGE_DIR_ITEM;
                                                    GLOBALPTR:IMAGE_DIR_ITEM;
                                                    TLS:IMAGE_DIR_ITEM;
                                                    CONFIG:IMAGE_DIR_ITEM;
                                                    BOUND_IMPORT:IMAGE_DIR_ITEM;
                                                    IAT:IMAGE_DIR_ITEM;
                                                     end;
                             DUMB:ARRAY [1..24] OF BYTE;
                      end;

SECTION=record
               Name:packed array [0..IMAGE_SIZEOF_SHORT_NAME-1] of Char;
               VirtualSize:DWORD;
               VirtualAddress:DWORD;
               SizeOfRawData:DWORD;
               PointerToRawData:DWORD;
               PointerToRelocations:DWORD;
               PointerToLinenumbers:DWORD;
               NumberOfRelocations:WORD;
               NumberOfLinenumbers:WORD;
               Characteristics:DWORD;
        end;

CONST
MAX_SECTION_NUMBER= $10;

VAR
    PE_HEADER:record
                 IMAGE_NT_SIGNATURE:DWORD;
                 FILE_HEADER:IMAGE_FILE_HEADER;
                 OPTIONAL_HEADER:IMAGE_OPTIONAL_HEADER;
          end;
                 SECTION_HEADER:ARRAY [1..MAX_SECTION_NUMBER] of SECTION;


    var
    hFile:DWORD;
    e_lfanew:DWORD;
    EXE:WORD;
    i:integer;
    bread:dword;
    EPreal, EP, imagebase,nv,ns,fa,sa:cardinal;
    num,epsec:integer;
    pe:pe_file;
    PACKEDSECTION:dword;
    PACKEDPOS:pointer;
    temp1:pointer;
    temp2:pointer;

// DEPACKER vars
    depbegin:dword;
    stra:string;
    iat:array[1..$b1] of byte;
    sizeofsec:dword;
    addrsec:dword;
    iatrva:dword;

Function RVA2Offset(RVA:DWORD):DWORD;
 var i:integer;
     VirtAddr,VA2,szRawData,ptrRawData:DWORD;
 begin
  for i:=1 to PE_HEADER.FILE_HEADER.NumberOfSections do
   begin
    VirtAddr:=SECTION_HEADER[i].VirtualAddress;
    szRawData:=SECTION_HEADER[i].SizeOfRawData;
    ptrRawData:=SECTION_HEADER[i].PointerToRawData;
    if RVA>=VirtAddr then
     begin
      VA2:=VirtAddr+szRawData;
      if RVA<VA2 then
       begin
        RVA:=RVA-VirtAddr;
        RVA:=RVA+ptrRawData;
       end;
     end;
   end;
  RVA2Offset:=RVA;
 end;

function GetLoaderSize(Func:dword):dword;
begin
asm
pushad
mov eax, func
mov esi, 1
@find:
mov dword ptr ebx, [eax]
mov dword ptr ecx, [eax+4]
cmp ebx, $41504544
jnz @notf
cmp ecx, $4E454B43
jnz @notf
mov result, esi
jmp @exit
@notf:
inc esi
inc eax
jmp @find
@exit:
popad
end;
end;

procedure ImportTable;
begin
{
0045F6A4  E8 F6 05 00 00 00 00 00 00 00 00 00 F8 F6 05 00  èö.........øö.
0045F6B4  E8 F6 05 00 E0 F6 05 00 00 00 00 00 00 00 00 00  èö.àö.........
0045F6C4  05 F7 05 00 E0 F6 05 00 00 00 00 00 00 00 00 00  ÷.àö.........
0045F6D4  00 00 00 00 00 00 00 00 00 00 00 00 58 12 DA 77  ............XÚw
0045F6E4  00 00 00 00 79 BB E6 77 1F A0 E6 77 C4 EF ED 77  ....y»æw æwÄïíw
0045F6F4  00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C  ....KERNEL32.dll
0045F704  00 55 53 45 52 33 32 2E 64 6C 6C 00 00 00 47 65  .USER32.dll...Ge
0045F714  74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47  tProcAddress...G
0045F724  65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00  etModuleHandleA.
0045F734  00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00  ..LoadLibraryA..
0045F744  00 4D 65 73 73 61 67 65 42 6F 78 41 00 00 00 00  .MessageBoxA....
}
for i:=1 to $b1 do iat[i]:=0;

iat[1]:=Lo(DEPBEGIN-imagebase+$44);
iat[2]:=Hi(DEPBEGIN-imagebase+$44);
iat[3]:=Lo((DEPBEGIN-imagebase+$44) shr 16);
iat[4]:=Hi((DEPBEGIN-imagebase+$44) shr 16);

iat[13]:=Lo(DEPBEGIN-imagebase+$54);
iat[14]:=Hi(DEPBEGIN-imagebase+$54);
iat[15]:=Lo((DEPBEGIN-imagebase+$54) shr 16);
iat[16]:=Hi((DEPBEGIN-imagebase+$54) shr 16);

iat[17]:=Lo(DEPBEGIN-imagebase+$44);
iat[18]:=Hi(DEPBEGIN-imagebase+$44);
iat[19]:=Lo((DEPBEGIN-imagebase+$44) shr 16);
iat[20]:=Hi((DEPBEGIN-imagebase+$44) shr 16);

iat[21]:=Lo(DEPBEGIN-imagebase+$3C);
iat[22]:=Hi(DEPBEGIN-imagebase+$3C);
iat[23]:=Lo((DEPBEGIN-imagebase+$3C) shr 16);
iat[24]:=Hi((DEPBEGIN-imagebase+$3C) shr 16);

iat[33]:=Lo(DEPBEGIN-imagebase+$61);
iat[34]:=Hi(DEPBEGIN-imagebase+$61);
iat[35]:=Lo((DEPBEGIN-imagebase+$61) shr 16);
iat[36]:=Hi((DEPBEGIN-imagebase+$61) shr 16);

iat[37]:=Lo(DEPBEGIN-imagebase+$3C);
iat[38]:=Hi(DEPBEGIN-imagebase+$3C);
iat[39]:=Lo((DEPBEGIN-imagebase+$3C) shr 16);
iat[40]:=Hi((DEPBEGIN-imagebase+$3C) shr 16);

iat[61]:=Lo(DEPBEGIN-imagebase+$9F);
iat[62]:=Hi(DEPBEGIN-imagebase+$9F);
iat[63]:=Lo((DEPBEGIN-imagebase+$9F) shr 16);
iat[64]:=Hi((DEPBEGIN-imagebase+$9F) shr 16);

iat[69]:=Lo(DEPBEGIN-imagebase+$6C);
iat[70]:=Hi(DEPBEGIN-imagebase+$6C);
iat[71]:=Lo((DEPBEGIN-imagebase+$6C) shr 16);
iat[72]:=Hi((DEPBEGIN-imagebase+$6C) shr 16);

iat[73]:=Lo(DEPBEGIN-imagebase+$7D);
iat[74]:=Hi(DEPBEGIN-imagebase+$7D);
iat[75]:=Lo((DEPBEGIN-imagebase+$7D) shr 16);
iat[76]:=Hi((DEPBEGIN-imagebase+$7D) shr 16);

iat[77]:=Lo(DEPBEGIN-imagebase+$90);
iat[78]:=Hi(DEPBEGIN-imagebase+$90);
iat[79]:=Lo((DEPBEGIN-imagebase+$90) shr 16);
iat[80]:=Hi((DEPBEGIN-imagebase+$90) shr 16);

iat[85]:=byte('K');
iat[86]:=byte('E');
iat[87]:=byte('R');
iat[88]:=byte('N');
iat[89]:=byte('E');
iat[90]:=byte('L');
iat[91]:=byte('3');
iat[92]:=byte('2');
iat[93]:=byte('.');
iat[94]:=byte('D');
iat[95]:=byte('L');
iat[96]:=byte('L');

iat[98]:= byte('U');
iat[99]:= byte('S');
iat[100]:= byte('E');
iat[101]:=byte('R');
iat[102]:=byte('3');
iat[103]:=byte('2');
iat[104]:=byte('.');
iat[105]:=byte('D');
iat[106]:=byte('L');
iat[107]:=byte('L');

iat[111]:=byte('G');
iat[112]:=byte('e');
iat[113]:=byte('t');
iat[114]:=byte('P');
iat[115]:=byte('r');
iat[116]:=byte('o');
iat[117]:=byte('c');
iat[118]:=byte('A');
iat[119]:=byte('d');
iat[120]:=byte('d');
iat[121]:=byte('r');
iat[122]:=byte('e');
iat[123]:=byte('s');
iat[124]:=byte('s');

iat[128]:=byte('G');
iat[129]:=byte('e');
iat[130]:=byte('t');
iat[131]:=byte('M');
iat[132]:=byte('o');
iat[133]:=byte('d');
iat[134]:=byte('u');
iat[135]:=byte('l');
iat[136]:=byte('e');
iat[137]:=byte('H');
iat[138]:=byte('a');
iat[139]:=byte('n');
iat[140]:=byte('d');
iat[141]:=byte('l');
iat[142]:=byte('e');
iat[143]:=byte('A');

iat[147]:=byte('L');
iat[148]:=byte('o');
iat[149]:=byte('a');
iat[150]:=byte('d');
iat[151]:=byte('L');
iat[152]:=byte('i');
iat[153]:=byte('b');
iat[154]:=byte('r');
iat[155]:=byte('a');
iat[156]:=byte('r');
iat[157]:=byte('y');
iat[158]:=byte('A');

iat[162]:=byte('M');
iat[163]:=byte('e');
iat[164]:=byte('s');
iat[165]:=byte('s');
iat[166]:=byte('a');
iat[167]:=byte('g');
iat[168]:=byte('e');
iat[169]:=byte('B');
iat[170]:=byte('o');
iat[171]:=byte('x');
iat[172]:=byte('A');

end;

procedure PE_Loader; assembler;
begin
asm
// IAT
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL

ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
NOP //177 BYTES

jmp @next
// Allocating memory
// GetProcAddress  14

ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL

// GetModuleHandle  15
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL

// GlobalAlloc 11
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
// Kernel32.dll   12
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
// User32.dll    10
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
// Kernel base
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL
// user32 base
ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL

ADD BYTE PTR [EAX],AL
ADD BYTE PTR [EAX],AL


@next:
PUSHAD
push $11223344
mov eax, $11223344
call [eax]          // GetModuleHandleA
push $11223344     // GlobalAlloc
push eax
mov eax, $11223344 // GetProcaAddr
call [eax]
push $11223344    // Size of section
push $40
call eax
mov [$11223344], eax  // save globalalloc addr
mov edi,eax
mov esi, $11223344
pushad

    cld
    mov    dl, 80h
    xor    ebx, ebx

@literal:
    movsb
    mov    bl, 2
@nexttag:
    call   @getbit
    jnc    @literal

    xor    ecx, ecx
    call   @getbit
    jnc    @codepair
    xor    eax, eax
    call   @getbit
    jnc    @shortmatch
    mov    bl, 2
    inc    ecx
    mov    al, 10h
@getmorebits:
    call   @getbit
    adc    al, al
    jnc    @getmorebits
    jnz    @domatch
    stosb
    jmp    @nexttag
@codepair:
    call   @getgamma_no_ecx
    sub    ecx, ebx
    jnz    @normalcodepair
    call   @getgamma
    jmp    @domatch_lastpos

@shortmatch:
    lodsb
    shr    eax, 1
    jz     @donedepacking
    adc    ecx, ecx
    jmp    @domatch_with_2inc

@normalcodepair:
    xchg   eax, ecx
    dec    eax
    shl    eax, 8
    lodsb
    call   @getgamma
    cmp    eax, 32000
    jae    @domatch_with_2inc
    cmp    ah, 5
    jae    @domatch_with_inc
    cmp    eax, 7fh
    ja     @domatch_new_lastpos

@domatch_with_2inc:
    inc    ecx

@domatch_with_inc:
    inc    ecx

@domatch_new_lastpos:
    xchg   eax, ebp
@domatch_lastpos:
    mov    eax, ebp

    mov    bl, 1

@domatch:
    push   esi
    mov    esi, edi
    sub    esi, eax
    rep    movsb
    pop    esi
    jmp    @nexttag

@getbit:
    add     dl, dl
    jnz     @stillbitsleft
    mov     dl, [esi]
    inc     esi
    adc     dl, dl
@stillbitsleft:
   ret
@getgamma:
    xor    ecx, ecx
@getgamma_no_ecx:
    inc    ecx
@getgammaloop:
    call   @getbit
    adc    ecx, ecx
    call   @getbit
    jc     @getgammaloop
    ret
@donedepacking:
    POPAD

// Copy to prog block
mov ecx,$11223344
//mov ecx, $11223344 // sizeofsec
@loopim:
// Reserved
MOV EBX, [ECX+EAX]  // MOV EAX, [ECX+GlobalMem]
MOV [ECX+$11223344],EBX   // MOV [ECX+SectionAddr+imagebase],EAX
LOOP @loopim
NOP
NOP

// import recoverer

 MOV EDX, $11223344 //imagebase
 MOV ESI, $11223344 // original iat rva
 ADD ESI, EDX
@dum6:
 MOV EAX, [ESI+$0C]
 TEST EAX,EAX
 JE @end
 ADD EAX,EDX
 MOV EBX,EAX
push eax
mov eax, $11223344
call [eax]          // GetModuleHandleA
 TEST EAX,EAX
 JNZ @dum1
 PUSH EBX
mov eax, $11223344
call [eax]          // LoadLibraryA
@dum1:
 MOV [$11223344],EAX  //somebuf1
 MOV [$11223344],0     //somebuf2
@dum5:
 MOV EDX, $1122344
 MOV EAX, [ESI]
 TEST EAX, EAX
 JNZ @dum2
 MOV EAX,[ESI+$10]
@dum2:
 ADD EAX, EDX
 ADD EAX, [$11223344]  //somebuf2
 MOV EBX,[EAX]
 MOV EDI,[ESI+$10]
 ADD EDI,EDX
 ADD EDI,[$11223344]  //somebuf2
 TEST EBX, EBX
 JE @dum3
 TEST EBX, $80000000
 JNZ @dum4
 ADD EBX,EDX
 INC EBX
 INC EBX
@dum4:
 AND EBX, $0FFFFFFF
 PUSH EBX
 PUSH [$11223344]  //somebuf
mov eax, $11223344
call [eax]          // GetProcAddress
 MOV [EDI],EAX
 ADD [$11223344],4  //somebuf2
 JMP @dum5
@dum3:
 ADD ESI,$14
 MOV EDX, $11223344 //imagebase
 JMP @dum6
@end:

// Free mem
push $11223344
mov eax, $11223344
call [eax]          // GetModuleHandleA
push $11223344     // GlobalFree
push eax
mov eax, $11223344 // GetProcaAddr
call [eax]
mov edx, [$11223344] // get pointer to mem
push edx
call eax

// Jmp to oep
popad
mov edx, $11223344
jmp edx
nop

//=============================
  retn
	INC ESP	//'D'
	INC EBP	//'E'
	PUSH EAX//'P'
	INC ECX	//'A'
	INC EBX	//'C'
	DEC EBX	//'K'
	INC EBP	//'E'
	DEC ESI	//'N'
	INC ESP	//'D'
end;
end;



function CallBack(w0, w1, w2 : DWORD; cbparam : Pointer) : DWORD;
begin
  with form1 do
  begin
    PB.Position    := Round(w1/CurFileSz*100);
    ClearLog;
    AddLog('Please wait...');
    Application.ProcessMessages;
      Result := aP_pack_continue;
  end;
end;

function PackSection(source1:pointer; size:dword):pointer;
begin

  form1.CurFileSz:=size;
  form1.aPLib.Source   := source1;
  form1.aPLib.Length   := size;
  form1.aPlib.CallBack := @CallBack;

 form1.aPLib.Pack;
  form1.ClearLog;
    PACKEDSECTION:= form1.aPLib.Length;

  if form1.aPLib.Length = 0 then Exit;

    form1.AddLog('  Size of section: '+inttostr(form1.CurFileSz)+' byte(s)');
    form1.AddLog('Packed of section: '+inttostr(PACKEDSECTION)+' byte(s)');
    form1.AddLog(' Size of depacker: '+inttostr(GetLoaderSize(dword(@PE_Loader)))+' byte(s)');
    form1.AddLog(FormatFloat('            Ratio: ##%', (packedsection*100)/form1.CurFileSz));


result:=form1.aPLib.Destination;
end;

procedure InsertString(where:pointer; str:string; offs:dword);
var writ:cardinal;
begin
asm
mov eax, where
add eax, offs
mov where, eax
end;
WriteProcessMemory(GetCurrentProcess(),where,pointer(str),length(str),writ);
end;

procedure InsertBytes(where:pointer; to1:string; size:dword; offs:dword);
var writ:cardinal;
begin
asm
mov eax, where
add eax, offs
mov where, eax
end;
WriteProcessMemory(GetCurrentProcess(),where,pointer(to1),size,writ);
end;

function Reversed(slovo:dword):dword; assembler;
asm
mov eax, slovo
XCHG AL,AH
ROL EAX,16
XCHG AL,AH
mov result, eax
end;

procedure TForm1.packbuttonClick(Sender: TObject);
var
 wr:cardinal;
 FS: TFileStream;
 jk: integer;
begin
 if (form1.fileedit.Text='') or (fileexists(form1.fileedit.Text)=false) then
   begin
    ClearLog;
    AddLog('Cannot open file!');
    Exit;
   end;
 //  
 FS:=TFileStream.Create(fileedit.Text,fmOpenRead);
 jk:=FS.Size;
 FS.Free;
 //
 hFile:=CreateFileA(pchar(form1.fileedit.Text), GENERIC_READ + GENERIC_WRITE, FILE_SHARE_READ + FILE_SHARE_WRITE, NIL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
   if hFile=INVALID_HANDLE_VALUE then
    begin
   ClearLog;
   AddLog('Cannot open file!');
     Exit;
    end;
  ReadFile(hFile,EXE,2,bread,NIL);
   if EXE<>$5A4D then
    begin
     CloseHandle(hFile);
     Exit;
    end;
   SetFilePointer(hFile,$3C,NIL,FILE_BEGIN);
   ReadFile(hFile,e_lfanew,4,bread,NIL);
   SetFilePointer(hFile,e_lfanew,NIL,FILE_BEGIN);
   ReadFile(hFile,PE_HEADER,SizeOF(PE_HEADER),bread,NIL);
   if PE_HEADER.IMAGE_NT_SIGNATURE<>$00004550 then
    begin
   ClearLog;
   AddLog('Invalid executable file !');
      CloseHandle(hFile);
      Exit;
    end;
   for i:=1 to PE_HEADER.FILE_HEADER.NumberOfSections Do
   ReadFile(hFile,SECTION_HEADER[i],SizeOF(Section),bread,NIL);

   form1.StatusBar1.Panels.Items[0].Text:='Packing....';
   ClearLog;

   epreal:=PE_HEADER.OPTIONAL_HEADER.AddressOfEntryPoint+PE_HEADER.OPTIONAL_HEADER.ImageBase;
   ImageBase:=PE_HEADER.OPTIONAL_HEADER.ImageBase;
   EP := RVA2Offset(epreal - ImageBase);

   num:=PE_HEADER.FILE_HEADER.NumberOfSections;
   fa:=PE_HEADER.OPTIONAL_HEADER.FileAlignment;
   sa:=PE_HEADER.OPTIONAL_HEADER.SectionAlignment;
   // SECTION_HEADER[num].SizeOfRawData:=FileSize(fileedit.Text)-SECTION_HEADER[num].PointerToRawData;
   SECTION_HEADER[num].SizeOfRawData:=jk-SECTION_HEADER[num].PointerToRawData;
   SECTION_HEADER[num].VirtualSize:=SECTION_HEADER[num].SizeOfRawData;
// Adding depacker section
PE_HEADER.FILE_HEADER.NumberOfSections:=PE_HEADER.FILE_HEADER.NumberOfSections+1;
SECTION_HEADER[num+1].Name:='.data';
SECTION_HEADER[num+1].Characteristics:=$C0000040; // NOT EXECUTABLE!
SECTION_HEADER[num+1].PointerToRawData:=((SECTION_HEADER[num].PointerToRawData+SECTION_HEADER[num].SizeOfRawData+fa-1) div fa)*fa;
SECTION_HEADER[num+1].VirtualAddress:=((SECTION_HEADER[num].VirtualAddress+SECTION_HEADER[num].VirtualSize+sa-1) div sa)*sa;
SECTION_HEADER[num+1].VirtualSize:=$400;
SECTION_HEADER[num+1].SizeOfRawData:=$400;
PE_HEADER.OPTIONAL_HEADER.SizeOfImage:=SECTION_HEADER[num+1].VirtualAddress+SECTION_HEADER[num+1].VirtualSize;

   ns:= SECTION_HEADER[num].PointerToRawData+SECTION_HEADER[num].SizeOfRawData;
nv:=SECTION_HEADER[num+1].VirtualAddress;


  for i:=1 to PE_HEADER.FILE_HEADER.NumberOfSections do
   begin
   if (ep>=SECTION_HEADER[i].PointerToRawData)and
   (ep<(SECTION_HEADER[i].SizeOfRawData+SECTION_HEADER[i].PointerToRawData)) then begin
   epsec:=i; break;
   end;
   end;

   DEPBEGIN:=nv+imagebase;
   sizeofsec:=SECTION_HEADER[1].SizeOfRawData;

   iatrva:=PE_HEADER.OPTIONAL_HEADER.IMAGE_DIRECTORY_ENTRIES.IMPORT.VirtualAddress;

// Writing Loader data //
// REALLY LAME METHOD  //
// DONT USE iT!        //
stra:='1234';

InsertString(@PE_Loader,'GlobalAlloc',179);
InsertString(@PE_Loader,'GlobalFree',191);
// Write number of sections
// Push Kernel32
asm
mov eax, stra
mov ebx, DEPBEGIN
add ebx, $54
mov [eax], ebx
end;
InsertBytes(@PE_Loader,stra,4,$101);
// mov eax, GetModuleHandleA
asm
mov eax, stra
mov ebx, DEPBEGIN
add ebx, $48
mov [eax], ebx
end;
InsertBytes(@PE_Loader,stra,4,$106);

asm
mov eax, stra
mov ebx, DEPBEGIN
add ebx, 179
mov [eax], ebx
end;
InsertBytes(@PE_Loader,stra,4,$10D);

asm
mov eax, stra
mov ebx, DEPBEGIN
add ebx, $44
mov [eax], ebx
end;
InsertBytes(@PE_Loader,stra,4,$113);

// push section size
asm
mov eax, stra
mov ebx, sizeofsec
mov [eax], ebx
end;
InsertBytes(@PE_Loader,stra,4,$11A);
// save globalalloc address
asm
mov eax, stra
mov ebx, DEPBEGIN
add ebx, 202
mov [eax], ebx
end;
InsertBytes(@PE_Loader,stra,4,$124);
// mov edi, SECTION_HEADER[1].PointerToRawData
addrsec:=SECTION_HEADER[1].VirtualAddress+imagebase;
asm
mov eax, stra
mov ebx, addrsec
mov [eax], ebx
end;
InsertBytes(@PE_Loader,stra,4,$12B);
// mov ecx, sizeofsec
asm
mov eax, stra
mov ebx, sizeofsec
sub ebx, 4
mov [eax], ebx
end;
InsertBytes(@PE_Loader,stra,4,$1C8);

// loop addr
asm
mov eax, stra
mov ebx, addrsec
mov [eax], ebx
end;
InsertBytes(@PE_Loader,stra,4,$1D1);

// write imagebase
asm
mov eax, stra
mov ebx, imagebase
mov [eax], ebx
end;
InsertBytes(@PE_Loader,stra,4,$1DA);
// original iat rva
asm
mov eax, stra
mov ebx, iatrva
mov [eax], ebx
end;
InsertBytes(@PE_Loader,stra,4,$1DF);
// mov eax, GetModuleHandle
asm
mov eax, stra
mov ebx, DEPBEGIN
add ebx, $48
mov [eax], ebx
end;
InsertBytes(@PE_Loader,stra,4,$1F6);
// LoadLibraryA
asm
mov eax, stra
mov ebx, DEPBEGIN
add ebx, $4C
mov [eax], ebx
end;
InsertBytes(@PE_Loader,stra,4,$202);

// mov somebuf1
asm
mov eax, stra
mov ebx, DEPBEGIN
add ebx, 206
mov [eax], ebx
end;
InsertBytes(@PE_Loader,stra,4,$20A);

// mov somebuf2
asm
mov eax, stra
mov ebx, DEPBEGIN
add ebx, 210
mov [eax], ebx
end;
InsertBytes(@PE_Loader,stra,4,$210);
// write imagebase
asm
mov eax, stra
mov ebx, imagebase
mov [eax], ebx
end;
InsertBytes(@PE_Loader,stra,4,$219);
InsertBytes(@PE_Loader,stra,4,$26E);
// somebuf2
asm
mov eax, stra
mov ebx, DEPBEGIN
add ebx, 210
mov [eax], ebx
end;
InsertBytes(@PE_Loader,stra,4,$22A);
InsertBytes(@PE_Loader,stra,4,$237);
InsertBytes(@PE_Loader,stra,4,$263);

// mov somebuf1
asm
mov eax, stra
mov ebx, DEPBEGIN
add ebx, 206
mov [eax], ebx
end;
InsertBytes(@PE_Loader,stra,4,$254);
// GetProcAddress
asm
mov eax, stra
mov ebx, DEPBEGIN
add ebx, $44
mov [eax], ebx
end;
InsertBytes(@PE_Loader,stra,4,$259);


//======================

// Push Kernel32
asm
mov eax, stra
mov ebx, DEPBEGIN
add ebx, $54
mov [eax], ebx
end;
InsertBytes(@PE_Loader,stra,4,$278);
// mov eax, GetModuleHandleA
asm
mov eax, stra
mov ebx, DEPBEGIN
add ebx, $48
mov [eax], ebx
end;
InsertBytes(@PE_Loader,stra,4,$27d);

asm
mov eax, stra
mov ebx, DEPBEGIN
add ebx, 191
mov [eax], ebx
end;
InsertBytes(@PE_Loader,stra,4,$284);

asm
mov eax, stra
mov ebx, DEPBEGIN
add ebx, $44
mov [eax], ebx
end;
InsertBytes(@PE_Loader,stra,4,$28A);

asm
mov eax, stra
mov ebx, DEPBEGIN
add ebx, 202
mov [eax], ebx
end;
InsertBytes(@PE_Loader,stra,4,$292);

// OEP
asm
mov eax, stra
mov ebx, epreal
mov [eax], ebx
end;
InsertBytes(@PE_Loader,stra,4,$29B);




ImportTable;
// Write IAT to depacker
WriteProcessMemory(GetCurrentProcess(),@PE_Loader,@iat,sizeof(iat),wr);


// PACKING
   temp1:=pointer(GlobalAlloc(GMEM_ZEROINIT,SECTION_HEADER[1].SizeOfRawData));
   temp2:=pointer(GlobalAlloc(GMEM_ZEROINIT,SECTION_HEADER[1].SizeOfRawData));

   SetFilePointer(hFile,SECTION_HEADER[1].PointerToRawData,NIL,FILE_BEGIN);
   ReadFile(hFile,temp1^,SECTION_HEADER[1].SizeOfRawData,bread,NIL);

   PACKEDPOS:= PackSection(pointer(temp1),SECTION_HEADER[1].SizeOfRawData);

// Clean section
   SetFilePointer(hFile,SECTION_HEADER[1].PointerToRawData,NIL,FILE_BEGIN);
   WriteFile(hFile,temp2^,SECTION_HEADER[1].SizeOfRawData,bread,NIL);
   GlobalFree(cardinal(temp2));

   SetFilePointer(hFile,SECTION_HEADER[1].PointerToRawData,NIL,FILE_BEGIN);
   WriteFile(hFile,PACKEDPOS^,PACKEDSECTION,bread,NIL);
    GlobalFree(cardinal(temp1));

    // end write packed sections
PE_HEADER.OPTIONAL_HEADER.AddressOfEntryPoint:=nv+$0FF;
PE_HEADER.OPTIONAL_HEADER.IMAGE_DIRECTORY_ENTRIES.IMPORT.VirtualAddress:=nv;
PE_HEADER.OPTIONAL_HEADER.IMAGE_DIRECTORY_ENTRIES.IMPORT.Size:=$b1;

   SetFilePointer(hFile,ns,NIL,FILE_BEGIN);
   temp2:=@PE_Loader;
   WriteFile(hFile,temp2^,GetLoaderSize(dword(@PE_Loader)),bread,NIL);

   for i:=1 to PE_HEADER.FILE_HEADER.NumberOfSections do
   SECTION_HEADER[i].Characteristics:=$E00000E0;

   SetFilePointer(hFile,e_lfanew,NIL,FILE_BEGIN);
   WriteFile(hFile,PE_HEADER,SizeOF(PE_HEADER),bread,NIL);
   for i:=1 to PE_HEADER.FILE_HEADER.NumberOfSections do
   WriteFile(hFile,SECTION_HEADER[i],SizeOF(Section),bread,NIL);

   CloseHandle(hFile);
   form1.StatusBar1.Panels.Items[0].Text:='Optimizing...';
   AddLog('Optimizing...');

   pe:=pe_file.Create;
   pe.LoadFromFile(form1.fileedit.Text);
   pe.OptimizeHeader(true);
   pe.OptimizeFileAlignment;
   pe.FlushFileCheckSum;
   pe.OptimizeFile(true,true,true,false);
   pe.SaveToFile(form1.fileedit.Text);
   pe.Free;
   AddLog('File successfully packed');

   form1.StatusBar1.Panels.Items[0].Text:='File is packed!';
end;

///////////////////////////// INTERFACE ////////////////////////////////////////

procedure TForm1.AddLog(text:string);
begin
form1.log.Lines.Add(text);
end;

procedure TForm1.ClearLog;
begin
form1.log.Lines.Clear;
end;

procedure TForm1.XPButton1Click(Sender: TObject);
begin
if Form1.OpenFiler.Execute then begin
form1.fileedit.Text:=form1.OpenFiler.FileName;
end;
end;

procedure TForm1.FormCreate(Sender: TObject);
begin
form1.Caption:=packer_ver;
end;

procedure TForm1.clocksTimer(Sender: TObject);
begin
form1.StatusBar1.Panels.Items[1].Text:=timetostr(now);
end;

end.


