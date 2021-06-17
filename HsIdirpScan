{

 * Demo Port Scanner Free Open Source Version Release
    coded by Hs32-Idir
     http://www.Hs32-Idir.tk

 ADVANCED :
 |--------------------------------------------------|
 | - Scan a multiple posts on multiple hosts.       |
 | - Can do scan for a range ports (From->To).      |
 | - Can Check only the specified port.             |
 | - Automatique Resolve IP from DNS/Hosts.         |
 | - Possibility to load data from file.            |
 | - Command line application.                      |
 | - Fast when resolving host & scanning.           |
 | - Multi Threading.                               |
 | - Advanced and freeware open source version. :D  |
 | - Show details about port type.                  |
 |--------------------------------------------------|

 * That will give me pleasure if you take some time to make me feedback,
  and please give credit if you use this source in your application.

}

program HsIdirpScan;

{$APPTYPE CONSOLE}
{$O+}

uses Windows,HsIdirStrList,Winsock;

resourcestring

  INVALID_ARG = ': Isn''t a valid argument that will be replaced with the arg maxi.' + #13#10 + 'Automatic corrected Arg';
  INVALID_MA  = ': Isn''t a valid argument that will be replaced with the arg Mini.' + #13#10 + 'Automatic corrected Arg';
  INVALID_MP  = ': Isn''t a valid port that will be replaced with the Port Mini.' + #13#10 + 'Automatic corrected Port';
  INVALID_PRT = ': Isn''t a valid port and replaced with the port maxi.' + #13#10 + 'Automatic corrected Port';
  INVALID_RNG = ': Isn''t a valid port range will replaced and set the minimum and maximum'+#13#10 + 'Automatic corrected range';
  CODER_NAME  = 'HsIdir-pScan Demo Port Scanner v-0.1 (Open Source Edition Release)';
  OUT_DBG     = 'HsIdir-pScan V-0.1';
  ERROR_IP    = 'Can''t be Resolved';
  STAT_A      = 'Opened';
  STAT_B      = 'Closed';

const
  IPPORT_HTTP = 80;
  RAW_SOCK    = 0;
  HSIDIR_TCP  = 3232;

Type
 TSocketInfo = record
  SocksPort:String;
  SocksHost:String;
  SocksTime:Integer;
  ShowOpened,ShowClosed:Boolean;
end;
 PSocketInfo = ^TSocketInfo;
var
 SetSocketInfo:TSocketInfo;
 SocksThreadID:Cardinal;

Type
 TGlobalThread = record
  PortList:TStringList;
  ShowOpened,ShowClosed:Boolean;
end;
 PGlobalThread = ^TGlobalThread;
var
 SetGlobalThreadInfo:TGlobalThread;
 GlobalThreadID:Cardinal;

Type
 TDataInfo = record
  Host:String;
  PortRange:String;
  ShowOpened,ShowClosed:Boolean;
end;
 PDataInfo = ^TdataInfo;
var
 SetDataInfo : TDataInfo;

function
{
 Application Process message translation
 Still Beta
}
 ProcessMessage(var Msg: TMsg): Boolean;
begin
  Result := False;
 if PeekMessage(Msg, 0, 0, 0, PM_REMOVE) then
  begin
    Result := True;
   if Msg.Message <> $0012 then
    begin
      TranslateMessage(Msg);
      DispatchMessage(Msg);
    end
   else
     Result := True;
     ExitProcess(0);
  end;
end;

procedure
{
 Do Message Translation
}
 ProcessMessages;
var
  Msg: TMsg;
begin
  while ProcessMessage(Msg) do {[NO_STOP]};
end;

function
{
 Close the main thread
  when finish the Test
}
CloseMainThread():Cardinal;
begin
  GetExitCodeThread(GetCurrentThread , Result);
  TerminateThread(GetCurrentThread , Result);
end;

function GetPortType(
{
 Port type resolver
  give the port number with type
}
const sPort:String):string;
var
 Port:Integer;
begin
  Val(sPort , Port , Port);
  Result := '(' + sPort + ' Any)';
 case Port of
  IPPORT_ECHO  : result := '(7 Echo)';
  IPPORT_DISCARD  : result := '(9 Discard)';
  IPPORT_SYSTAT  : result := '(11 SysTat)';
  IPPORT_DAYTIME  : result := '(13 DayTime)';
  IPPORT_NETSTAT  : result := '(15 NetStat)';
  IPPORT_FTP  : result := '(21 Ftp)';
  IPPORT_TELNET  : result := '(23 Telnet)';
  IPPORT_SMTP  : result := '(25 Smtp)';
  IPPORT_TIMESERVER  : result := '(37 TimeServer)';
  IPPORT_NAMESERVER  : result := '(42 NameServer)';
  IPPORT_WHOIS  : result := '(43 WhoIs)';
  IPPORT_MTP  : result := '(57 Mtp)';
  IPPORT_HTTP : result := '(80 Http)';
  RAW_SOCK : result := '(0 Raw)';
  HSIDIR_TCP : result := '(3232 HsIdir TroJan)';
  //see, you can add here more port with descriptions
  //exemp : 8080 : result := '(8080 Bifrost Trojan)';
 end;
end;

function SocksThread(pData:Pointer):Integer; stdcall;
type
  Taddr = array[0..100] of pinaddr;
  Paddr = ^taddr;
var
  HsIdirSock:TSocket;
  HsIdirWSAData:TWSAData;
  HsIdirSockAddrIn :TSockAddrIn;
  HsIdirHostEnt:PHostEnt;
  HsIdirAddr:Paddr;
  ShowOpened,ShowClosed:Boolean;
  sPort,sTime,Loop:Integer;
  sHost,Port,AddressIP:String;
Label DiSco;
begin
  result := -1;
  if PSocketInfo(pData)^.SocksPort = '' then Exit;
  Val( PSocketInfo(pData)^.SocksPort , sPort , sPort);
  sTime := PSocketInfo(pData)^.SocksTime;

  sHost := PSocketInfo(pData)^.SocksHost;
  ShowOpened := PSocketInfo(pData)^.ShowOpened;
  ShowClosed := PSocketInfo(pData)^.ShowClosed;
  Str(sPort,Port);

  Sleep(sTime);
  WSAStartup($0101,HsIdirWSAData);

  HsIdirSock                       := Socket(AF_INET,SOCK_STREAM,IPPROTO_IP);
  HsIdirSockAddrIn.sin_family      := AF_INET;
  HsIdirSockAddrIn.sin_port        := htons(SPort);
  HsIdirSockAddrIn.sin_addr.S_addr := inet_addr(pChar(sHost));

  if HsIdirSockAddrIn.sin_addr.S_addr = INADDR_NONE then
  begin
    HsIdirHostEnt := Gethostbyname(pChar(sHost));
    if HsIdirHostEnt <> nil then
    begin
      HsIdirSockAddrIn.sin_addr.S_addr := Longint(PLongint(HsIdirHostEnt^.h_addr_list^)^);
      HsIdirAddr := paddr(HsIdirHostEnt^.h_addr_list);
      loop := 0;
      while (HsIdirAddr^[loop] <> nil) do
      begin
        AddressIP := inet_ntoa(HsIdirAddr^[loop]^);
        inc(loop);
      end;
    end
   else
    begin
      AddressIP := ERROR_IP;
      Exit;
    end;
    if AddressIP = '' then AddressIP := '0.0.0.0';
  end;

  If (HsIdirSock = INVALID_SOCKET) Then Exit;
  if Connect(HsIdirSock,HsIdirSockAddrIn,SizeOf(HsIdirSockAddrIn)) = 0 then
   begin
    if ShowOpened then
     WriteLn('[ ' + sHost  + '/'+ AddressIP +' ] Has : ' + GetPortType(Port) + ' |'+STAT_A+'|' );
    Goto DisCo;
   end
  else
   begin
    if ShowClosed then
     WriteLn('[ ' + sHost  + '/'+ AddressIP +' ] Has : ' + GetPortType(Port) + ' |'+STAT_B+'|' );
    Goto DisCo;
   end;
 DisCo :
  begin
    CloseSocket(HsIdirSock);
    WSACleanUP();
    CloseMainThread();
  end;
end;

function SplitePort(pData:Pointer):Integer; stdcall;
var
 PortRange,Host,pA,pB,tPort,sPort:String;
 I,COUNT:Byte;
 T,A,B,P:Integer;
begin
  Result := -1;
  Host := PDataInfo(pData)^.Host;
  PortRange := PDataInfo(pData)^.PortRange;
  if PortRange[Length(PortRange)] <> ',' then PortRange := PortRange + ',';
  COUNT := 0;
  for i := 0 to Length(PortRange) do if Pos(',',PortRange)>1 then Inc(COUNT);
  for I := 0 to COUNT-1 do //Length(PortRange) do
  begin
    tPort := Copy( PortRange , 0 , Pos(',',Portrange)-1);
    if tPort = '' then Exit;
    Delete(PortRange , 1 ,Pos(',' , PortRange));
    if Pos('-',tPort) > 1 then
    begin
      pA := Copy( tPort , 0 , Pos('-',tPort)-1);
      pB := Copy( tPort , Pos('-',tPort)+1 , MAXINT);
      Val(pA , A , A);
      Val(pB , B , B);
      If A > B then
      begin
        WriteLn(pA +'-'+pB + INVALID_RNG);
        A := B - 1;
      end;
      if (B > 65536) Then
      begin
        WriteLn(pB + INVALID_ARG);
        B := 65536;
      end
     else
      if (A <= -1) Then
      begin
        WriteLn(pA + INVALID_MA);
        A := 0;
      end;
      for T := A To B do
      begin
        Str(T , sPort);
        SetSocketInfo.SocksPort := sPort;
        SetSocketInfo.SocksHost := Host;
        SetSocketInfo.SocksTime := Random(515);
        SetSocketInfo.ShowOpened := PDataInfo(pData)^.ShowOpened;
        SetSocketInfo.ShowClosed := PDataInfo(pData)^.ShowClosed;
        CreateThread(nil , 0 , @SocksThread , @SetSocketInfo , 0 , SocksThreadID);
        ProcessMessages;
        Sleep(Random(50));
      end;
    end
   else
    begin
      Val(tPort , P , P);
      if (P > 65536) then
      begin
        WriteLn(tPort + INVALID_PRT);
        tPort := '65536';
      end
     else 
      if (P <= -1) then
      begin
        WriteLn(tPort + INVALID_MP);
        tPort := '0';
      end; 
      SetSocketInfo.SocksPort := tPort;
      SetSocketInfo.SocksHost := Host;
      SetSocketInfo.SocksTime := Random(315);
      SetSocketInfo.ShowOpened := PDataInfo(pData)^.ShowOpened;
      SetSocketInfo.ShowClosed := PDataInfo(pData)^.ShowClosed;
      CreateThread(nil , 0 , @SocksThread , @SetSocketInfo , 0 , SocksThreadID);
      Sleep(Random(50));
    end;

  end;
end;

function SpliteData(
{
 Load the Port/host list
}
):TStringList;
begin
  Result := TStringList.Create;
  Result.LoadFromFile('Data.Txt');
end;

function HandleCheckData(
{
 Global function splite
 informations and check Data
}
pData:Pointer

):Integer; stdcall;
var
 PortList:TStringList;
 Host,Port:String;
 PortThreadID:Cardinal;
 I:Byte;
begin
  Result := -1;
  PortList := pGlobalThread(pData)^.PortList;
  for I := 0 to PortList.Count -1 do
  begin
    Host := Copy( PortList.Strings[I] , 0 , Pos(',',PortList.Strings[I])-1);
    Port := Copy( PortList.Strings[I] , Pos(',' , PortList.Strings[I])+1 , MAXINT);
    SetDataInfo.Host := Host;
    SetDataInfo.PortRange := Port;
    SetdataInfo.ShowOpened := pGlobalThread(pData)^.ShowOpened;
    SetdataInfo.ShowClosed := pGlobalThread(pData)^.ShowClosed;
    CreateThread(nil , 0 , @SplitePort , @SetDataInfo , 0  , PortThreadID);
    ProcessMessages;
  end;
end;

procedure ShowHelp();
begin
  WriteLn('Welcome, ');
  WriteLn(' Commands :');
  WriteLn('   the command "-h" to specify host/dns/ip');
  WriteLn('   to specify ports you must use command "-p"');
  WriteLn('   when specify what type of port (Closed/Opened)'+ #13#10+
          '   will be shown during the scan we use commands "-s-a" , "-s-o" , "-s-c"' + #13#10 +
          '     -s-a : that means that the thread will show all scanned ports' + #13#10 +
          '     -s-o : that means that the thread will show only opened ports' + #13#10 +
          '     -s-c : that means that the thread will show only closed ports');
  WriteLn('');
  WriteLn('To Specify ports to scan for example : ');
  WriteLn(' Range of ports, you must type 5-10 this will scan from 5 to 10');
  WriteLn(' List of ports, you must separate with (,) between each port, exmp : (5,8,10) this will scan 5 and 8 and 10');
  WriteLn(' Scanning a single port just type the port number after the command -p, exmp : (-p 80) this will scan 80');
  WriteLn('');
  WriteLn('   Show this help -?');
  WriteLn('');
  WriteLn('Usage :');
  WriteLn(' HsIdir-pScan -h Target.url -p 0-80 -s-o');
  WriteLn('');
  WriteLn('NOTE :');
  WriteLn('  You Can use it without command line , running it directly '+#13#10+
          '  but before you do that you must edit the "Data.txt" at the first.' +#13#10+
          '  You must exclude the "http://" from the url'+#13#10+
          '  For the commands you can type them in lowercase or in uppercase');
  Exit;
end;

Var
 MSG:TMSG;
 C:Integer;
 hData,pData,aShow,Cmd:string;
 TempData:TStringList;
begin
  OutPutDebugString(pAnsiChar(OUT_DBG));
  WriteLn(CODER_NAME);
  WriteLn(' - Coded By Hs32-Idir');
  WriteLn('');
  WriteLn('ConTact : http://www.Hs32-Idir.tk');
  WriteLn('');
  Randomize;
  if ParamCount > 0 then
  begin
    for C := 0 to ParamCount  do
    begin
     if ((Pos('-h',ParamStr(C))>0) or (Pos('-H',Paramstr(C))>0)) then hData := ParamStr(C+1) else
     if ((Pos('-p',Paramstr(C))>0) or (Pos('-P',Paramstr(C))>0)) then pData := Paramstr(C+1) else
     if ((Pos('-?',Paramstr(C))>0) or (Pos('help',Paramstr(C))>0)) then Cmd := 'h' else
     if ((Pos('-s',Paramstr(C))>0) or (Pos('-S',Paramstr(C))>0)) then aShow := Copy(Paramstr(C),4,1);
     ProcessMessages;
    end;   
    if (Cmd = 'h') then ShowHelp else
    begin
      Writeln('------------------------- Begin Scanning -------------------------');
      WriteLn('');
    end;
    if (aShow = 'a') or (ashow = 'A') then
    begin
      TempData := TStringList.Create;
      TempData.Add(hData + ',' + pData);
      SetGlobalThreadInfo.PortList := TempData;
      SetGlobalThreadInfo.ShowOpened := true;
      SetGlobalThreadInfo.ShowClosed := true;
      CreateThread(Nil , 0 , @HandleCheckData , @SetGlobalThreadInfo , 0 , GlobalThreadID);
      Sleep(Random(300));
      TempData.Free;
    end
   else
  if (aShow = 'o') or (ashow = 'O') then
   begin
     TempData := TStringList.Create;
     TempData.Add(hData + ',' + pData);
     SetGlobalThreadInfo.PortList := TempData;
     SetGlobalThreadInfo.ShowOpened := true;
     SetGlobalThreadInfo.ShowClosed := false;
     CreateThread(Nil , 0 , @HandleCheckData , @SetGlobalThreadInfo , 0 , GlobalThreadID);
     Sleep(Random(300));
     TempData.Free;
   end
  else
 if (aShow = 'c') or (ashow = 'C') then
  begin
    TempData := TStringList.Create;
    TempData.Add(hData + ',' + pData);
    SetGlobalThreadInfo.PortList := TempData;
    SetGlobalThreadInfo.ShowOpened := false;
    SetGlobalThreadInfo.ShowClosed := true;
    CreateThread(Nil , 0 , @HandleCheckData , @SetGlobalThreadInfo , 0 , GlobalThreadID);
    Sleep(Random(300));
    TempData.Clear;
  end;
 end
else
 begin
   Writeln('------------------------- Begin Scanning -------------------------');
   WriteLn('');
   SetGlobalThreadInfo.PortList := SpliteData;
   SetGlobalThreadInfo.ShowOpened := true;
   SetGlobalThreadInfo.ShowClosed := true;
   CreateThread(Nil , 0 , @HandleCheckData , @SetGlobalThreadInfo , 0 , GlobalThreadID);
   Sleep(Random(300));
   SpliteData.Clear;
 end;

 while GetMessage(MsG,0,0,0) do
 begin
   TranslateMessage(MsG);
   DispatchMessage(MsG);
 end;
 Halt(MsG.wParam);

end.
