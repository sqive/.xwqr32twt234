Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "SystemRestorePointCreationFrequency" /t REG_DWORD /d "0" /f 
powershell -ExecutionPolicy Bypass -Command "Checkpoint-Computer -Description 'Aphinity Network Backup' -RestorePointType 'MODIFY_SETTINGS'" 

:NetworkTweaks
cls

:: Reset Internet
echo Resetting Internet
ipconfig /release
ipconfig /renew
ipconfig /flushdns
netsh int ip reset
netsh int ipv4 reset
netsh int ipv6 reset
netsh int tcp reset
netsh winsock reset
netsh advfirewall reset
netsh branchcache reset
netsh http flush logbuffer
timeout /t 3 /nobreak > NUL

:: Enable MSI Mode for Network Adapter
echo Enabling MSI Mode for Network Adapter
for /f %%l in ('wmic path win32_NetworkAdapter get PNPDeviceID ^| find "PCI\VEN_"') do (
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\SYSTEM\CurrentControlSet\Enum\%%l\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f 
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\SYSTEM\CurrentControlSet\Enum\%%l\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /t REG_DWORD /d "0" /f 
)
timeout /t 1 /nobreak > NUL

:: Disable Network Throttling
echo Disabling Network Throttling
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f 
timeout /t 1 /nobreak > NUL

:: Set Network Autotuning to Disabled
echo Setting Network AutoTuning to Disabled
netsh int tcp set global autotuninglevel=disabled
timeout /t 1 /nobreak > NUL

:: Disable ECN
echo Disabling Explicit Congestion Notification
netsh int tcp set global ecncapability=disabled
timeout /t 1 /nobreak > NUL

:: Enable DCA
echo Enabling Direct Cache Access
netsh int tcp set global dca=enabled
timeout /t 1 /nobreak > NUL

:: Enable NetDMA
echo Enabling Network Direct Memory Access
netsh int tcp set global netdma=enabled
timeout /t 1 /nobreak > NUL

:: Disable RSC
echo Disabling Recieve Side Coalescing
netsh int tcp set global rsc=disabled
timeout /t 1 /nobreak > NUL

:: Enable RSS
echo Enabling Recieve Side Scaling
netsh int tcp set global rss=enabled
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Ndis\Parameters" /v "RssBaseCpu" /t REG_DWORD /d "1" /f 
timeout /t 1 /nobreak > NUL

:: Disable TCP Timestamps
echo Disabling TCP Timestamps
netsh int tcp set global timestamps=disabled
timeout /t 1 /nobreak > NUL

:: Set Initial RTO to 2ms
echo Setting Initial Retransmission Timer
netsh int tcp set global initialRto=2000
timeout /t 1 /nobreak > NUL

:: Set MTU Size to 1500
echo Setting MTU Size
netsh interface ipv4 set subinterface “Ethernet” mtu=1500 store=persistent
timeout /t 1 /nobreak > NUL

:: Disable NonSackRTTresiliency
echo Disabling Non Sack RTT Resiliency
netsh int tcp set global nonsackrttresiliency=disabled
timeout /t 1 /nobreak > NUL

:: Set Max Syn Retransmissions to 2
echo Setting Max Syn Retransmissions
netsh int tcp set global maxsynretransmissions=2
timeout /t 1 /nobreak > NUL

:: Disable MPP
echo Disabling Memory Pressure Protection
netsh int tcp set security mpp=disabled
timeout /t 1 /nobreak > NUL

:: Disable Security Profiles
echo Disabling Security Profiles
netsh int tcp set security profiles=disabled
timeout /t 1 /nobreak > NUL

:: Disable Heuristics
echo Disabling Windows Scaling Heuristics
netsh int tcp set heuristics disabled
timeout /t 1 /nobreak > NUL

:: Increase ARP Cache Size to 4096
echo Increasing ARP Cache Size
netsh int ip set global neighborcachelimit=4096
timeout /t 1 /nobreak > NUL

:: Enable CTCP
echo Enabling CTCP
netsh int tcp set supplemental Internet congestionprovider=ctcp
timeout /t 1 /nobreak > NUL

:: Disable Task Offloading
echo Disabling Task Offloading
netsh int ip set global taskoffload=disabled
timeout /t 1 /nobreak > NUL

:: Disable IPv6
echo Disabling IPv6
netsh int ipv6 set state disabled
timeout /t 1 /nobreak > NUL

:: Disable ISATAP
echo Disabling ISATAP
netsh int isatap set state disabled
timeout /t 1 /nobreak > NUL

:: Disable Teredo
echo Disabling Teredo
netsh int teredo set state disabled
timeout /t 1 /nobreak > NUL

:: Set TTL to 64
echo Configuring Time to Live
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f 
timeout /t 1 /nobreak > NUL

:: Enable TCP Window Scaling
echo Enabling TCP Window Scaling
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "1" /f 
timeout /t 1 /nobreak > NUL

:: Set TcpMaxDupAcks
echo Setting TcpMaxDupAcks to 2
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /f 
timeout /t 1 /nobreak > NUL

:: Disable SackOpts
echo Disabling TCP Selective ACKs
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "0" /f 
timeout /t 1 /nobreak > NUL

:: Increase Maximum Port Number
echo Increasing Maximum Port Number
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f 
timeout /t 1 /nobreak > NUL

:: Decrease Time to Wait in "TIME_WAIT" State
echo Decreasing Timed Wait Delay
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "30" /f 
timeout /t 1 /nobreak > NUL

:: Set Network Priorities
echo Setting Network Priorities
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f 
timeout /t 1 /nobreak > NUL

:: Adjust Sock Address Size
echo Configuring Sock Address Size
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "MinSockAddrLength" /t REG_DWORD /d "16" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "MaxSockAddrLength" /t REG_DWORD /d "16" /f 
timeout /t 1 /nobreak > NUL

:: Disable Nagle's Algorithm
echo Disabling Nagle's Algorithm
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TCPNoDelay" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f 
timeout /t 1 /nobreak > NUL

:: Disable Delivery Optimization
echo Disabling Delivery Optimization
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadMode" /t REG_DWORD /d "0" /f 
timeout /t 1 /nobreak > NUL

:: Disable Auto Disconnect for Idle Connections
echo Disabling Auto Disconnect
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "autodisconnect" /t REG_DWORD /d "4294967295" /f 
timeout /t 1 /nobreak > NUL

:: Limit Number of SMB Sessions
echo Limiting SMB Sessions
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f 
timeout /t 1 /nobreak > NUL

:: Disable Oplocks
echo Disabling Oplocks
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "EnableOplocks" /t REG_DWORD /d "0" /f 
timeout /t 1 /nobreak > NUL

:: Set IRP Stack Size
echo Setting IRP Stack Size
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "20" /f 
timeout /t 1 /nobreak > NUL

:: Disable Sharing Violations
echo Disabling Sharing Violations
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationDelay" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationRetries" /t REG_DWORD /d "0" /f 
timeout /t 1 /nobreak > NUL

:: Get the Sub ID of the Network Adapter
for /f %%n in ('Reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}" /v "*SpeedDuplex" /s ^| findstr  "HKEY"') do (

:: Disable NIC Power Savings
echo Disabling NIC Power Savings
Reg.exe add "%%n" /v "AutoPowerSaveModeEnabled" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "AutoDisableGigabit" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "AdvancedEEE" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "DisableDelayedPowerUp" /t REG_SZ /d "2" /f 
Reg.exe add "%%n" /v "*EEE" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "EEE" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "EnablePME" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "EEELinkAdvertisement" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "EnableGreenEthernet" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "EnableSavePowerNow" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "EnablePowerManagement" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "EnableDynamicPowerGating" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "EnableConnectedPowerGating" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "EnableWakeOnLan" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "GigaLite" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "NicAutoPowerSaver" /t REG_SZ /d "2" /f 
Reg.exe add "%%n" /v "PowerDownPll" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "PowerSavingMode" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "ReduceSpeedOnPowerDown" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "SmartPowerDownEnable" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "S5NicKeepOverrideMacAddrV2" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "S5WakeOnLan" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "ULPMode" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "WakeOnDisconnect" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "*WakeOnMagicPacket" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "*WakeOnPattern" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "WakeOnLink" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "WolShutdownLinkSpeed" /t REG_SZ /d "2" /f 
timeout /t 1 /nobreak > NUL

:: Disable Jumbo Frame
echo Disabling Jumbo Frame
Reg.exe add "%%n" /v "JumboPacket" /t REG_SZ /d "1514" /f 
timeout /t 1 /nobreak > NUL

:: Configure Receive/Transmit Buffers
echo Configuring Buffer Sizes
Reg.exe add "%%n" /v "ReceiveBuffers" /t REG_SZ /d "1024" /f 
Reg.exe add "%%n" /v "TransmitBuffers" /t REG_SZ /d "4096" /f 
timeout /t 1 /nobreak > NUL

:: Configure Offloads
echo Configuring Offloads
Reg.exe add "%%n" /v "IPChecksumOffloadIPv4" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "LsoV1IPv4" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "LsoV2IPv4" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "LsoV2IPv6" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "PMARPOffload" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "PMNSOffload" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "TCPChecksumOffloadIPv4" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "TCPChecksumOffloadIPv6" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "UDPChecksumOffloadIPv6" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "UDPChecksumOffloadIPv4" /t REG_SZ /d "0" /f 
timeout /t 1 /nobreak > NUL

:: Enable RSS in NIC
echo Enabling RSS in NIC
Reg.exe add "%%n" /v "RSS" /t REG_SZ /d "1" /f 
Reg.exe add "%%n" /v "*NumRssQueues" /t REG_SZ /d "2" /f 
Reg.exe add "%%n" /v "RSSProfile" /t REG_SZ /d "3" /f 
timeout /t 1 /nobreak > NUL

:: Disable Flow Control
echo Disabling Flow Control
Reg.exe add "%%n" /v "*FlowControl" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "FlowControlCap" /t REG_SZ /d "0" /f 
timeout /t 1 /nobreak > NUL

:: Remove Interrupt Delays
echo Removing Interrupt Delays
Reg.exe add "%%n" /v "TxIntDelay" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "TxAbsIntDelay" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "RxIntDelay" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "RxAbsIntDelay" /t REG_SZ /d "0" /f 
timeout /t 1 /nobreak > NUL

:: Remove Adapter Notification
echo Removing Adapter Notification Sending
Reg.exe add "%%n" /v "FatChannelIntolerant" /t REG_SZ /d "0" /f 
timeout /t 1 /nobreak > NUL

:: Disable Interrupt Moderation
echo Disabling Interrupt Moderation
Reg.exe add "%%n" /v "*InterruptModeration" /t REG_SZ /d "0" /f 
timeout /t 1 /nobreak > NUL
)

:: Enable WeakHost Send and Recieve (melodytheneko)
echo Enabling WH Send and Recieve
powershell "Get-NetAdapter -IncludeHidden | Set-NetIPInterface -WeakHostSend Enabled -WeakHostReceive Enabled -ErrorAction SilentlyContinue"
timeout /t 1 /nobreak > NUL