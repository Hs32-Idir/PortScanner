{-------------------------------------------------------------------------------}
{  Agent-Hs32-Idir[V-P] Release                                                 }
{                                                                               }
{  C-Right : Use And Abuse, But Dont Remove This Header From Code, And          }
{              Gimme A Shoutout If You Used It.                                 }
{                                                                               }
{  Author    : Hs32-Idir                                                        }
{  Website   : www.Hs32-Idir.110md.Com                                          }
{  Contact   : Hs32-Idir@VirusProducts.Hack                                     }
{  C-Right   : (c) 2006-2007                                                    }
{                                                                               }
{  What's  :                                                                    }
{  ~~~~~~~~                                                                     }
{                                                                               }
{  HsIdirStrList.Pas , Small-Unit.                                              }
{                                                                               }
{  -Big Thanks To : ~LOM~                                                       }
{-------------------------------------------------------------------------------}

UNIT HsIdirStrList;

INTERFACE

{$WARN SYMBOL_PLATFORM OFF}
{$WARN SYMBOL_LIBRARY OFF}
{$WARN SYMBOL_DEPRECATED OFF}
{$WARN UNIT_DEPRECATED OFF}
{$WARN UNIT_PLATFORM OFF}
{$WARN UNIT_LIBRARY OFF}
{$WARNINGS OFF}

USES Windows;

TYPE
  TfndFlags = (fndExact, fndIgnoreCase, fndPartial);
  TStringList = CLASS(TObject)
PRIVATE
    varCount: Integer;
    FHandle: HWnd;
PUBLIC
    Strings: ARRAY [0..65535] OF STRING;
    CONSTRUCTOR Create;
    DESTRUCTOR  Destroy;
    PROCEDURE   SaveToFile(Filename: STRING);
    PROCEDURE   LoadFromFile(Filename: STRING);
    PROCEDURE   Add(Text: STRING);
    PROCEDURE   Delete(Index: Integer);
    PROCEDURE   Clear;
    FUNCTION    IsCharInThis(Chars:STRING):Boolean;
    FUNCTION    Find(TextFind: STRING; Flag: TfndFlags = fndExact): Integer;
    FUNCTION    TextRead: STRING;
    PROCEDURE   TextModify(Input: STRING);
    PROPERTY    Count: Integer READ varCount;
    PROPERTY    Text: STRING READ TextRead WRITE TextModify;
    PROPERTY    Handle: HWnd READ FHandle;
END;

IMPLEMENTATION

//Create The String List And Initialise it
CONSTRUCTOR TStringList.Create;
BEGIN
  varCount := 0;
END;

// String List Destroy
DESTRUCTOR TStringList.Destroy;
BEGIN
  Clear;
  varCount := 0;
END;

//Load The String List From the specify File
PROCEDURE TStringList.LoadFromFile(FileName:STRING);
VAR
  F: TextFile;
  ReadContent: STRING;
BEGIN
  Clear;
  AssignFile(F, FileName);
  Reset(F);
WHILE NOT Eof(F) DO
BEGIN
    Readln(F, ReadContent);
    Strings[varCount] := ReadContent;
    Inc(varCount);
END;
    CloseFile(F);
END;

// Save the String List to the Specify file
PROCEDURE TStringList.SaveToFile(Filename: STRING);
VAR
  F: TextFile;
  i: Integer;
BEGIN
    AssignFile(F, Filename);
    ReWrite(F);
FOR i := 0 TO varCount-1 DO WriteLn(F, Strings[i]);
    CloseFile(F);
END;

//Add lines to the String List
PROCEDURE TStringList.Add(Text: STRING);
BEGIN
  Strings[varCount] := Text;
  Inc(varCount);
END;

//Verify if Char exists
FUNCTION TStringList.IsCharInThis(Chars:STRING):Boolean;
VAR
  i: Integer;
BEGIN
    Result := False;
FOR i := 0 TO varCount-1 DO
IF  Strings[i] = Chars THEN
    Result := TRUE
ELSE
    Result := FALSE;
END;

//clear the String List
PROCEDURE TStringList.Clear;
VAR
  i: Integer;
BEGIN
FOR i := 0 TO varCount-1 DO Strings[i] := '';
    varCount := 0;
END;

// Find Test In The String List
FUNCTION TStringList.Find(TextFind: STRING; Flag: TfndFlags = fndExact): Integer;
VAR
  i: Integer;
BEGIN
     Result := -1;
CASE Flag OF
     fndExact:
FOR  i := 0 TO varCount-1 DO
IF   Strings[i] = TextFind THEN
BEGIN
     Result := i;
     Break;
END;
     fndIgnoreCase:
FOR  i := 0 TO varCount-1 DO
IF   lstrcmp(Pchar(Strings[i]), Pchar(TextFind)) = 0 THEN
BEGIN
     Result := i;
     Break;
END;
     fndPartial:
FOR  i := 0 TO varCount-1 DO
IF   Pos(TextFind, Strings[i]) > 0 THEN
BEGIN
     Result := i;
     Break;
END;
END;
END;

// delete Item in the String List
PROCEDURE TStringList.Delete(Index: Integer);
VAR
  TempArray: ARRAY OF STRING;
  i, Increment: Integer;
BEGIN
IF  (Index < 0) OR (Index >= varCount) OR (varCount = 0) THEN
    Exit;
    Dec(varCount);
    SetLength(TempArray, varCount);
    Increment := 0;
FOR i := 0 TO varCount DO
IF  i <> Index THEN
BEGIN
    TempArray[Increment] := Strings[i];
    Inc(Increment);
END;
FOR i := 0 TO varCount-1 DO Strings[i] := TempArray[i];
  TempArray := NIL;
END;

//read text
FUNCTION TStringList.TextRead: STRING;
VAR
  i: Integer;
BEGIN
    Result := '';
FOR i := 0 TO varCount-1 DO
    Result := Result + Strings[i] + #10#13;
    Result := Copy(Result, 1, Length(Result)-Length(#10#13));
END;

//Modify text
PROCEDURE TStringList.TextModify(Input: STRING);
VAR
  i: Integer;
BEGIN
    Clear;
REPEAT
    i := Pos(#10#13, Input);
IF  i > 0 THEN
BEGIN
      Strings[varCount] := Copy(Input, 1, i-1);
      System.Delete(Input, 1, i+1);
END ELSE
      Strings[varCount] := Input;
      Inc(varCount);
UNTIL i = 0;
END;


{
 Writen by Agent-Hs32-Idir[V-P] 2006-07
}
END.
