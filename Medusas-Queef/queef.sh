#!/bin/bash

NO_COLOR="\e[0m"
WHITE="\e[0;17m"
BOLD_WHITE="\e[1;37m"
BLACK="\e[0;30m"
BLUE="\e[0;34m"
BOLD_BLUE="\e[1;34m"
GREEN="\e[0;32m"
BOLD_GREEN="\e[1;32m"
CYAN="\e[0;36m"
BOLD_CYAN="\e[1;36m"
RED="\e[0;31m"
BOLD_RED="\e[1;31m"
PURPLE="\e[0;35m"
BOLD_PURPLE="\e[1;35m"
BROWN="\e[0;33m"
BOLD_YELLOW="\e[1;33m"
GRAY="\e[0;37m"
BOLD_GRAY="\e[1;30m"
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
blue='\033[0;34m'
magenta='\033[0;35m'
cyan='\033[0;36m'
# Clear the color after that
clear='\033[0m'

function easyexit()
{
	clear
	exit
}

                     
function title() {
echo -e "$BOLD_GREEN

___  ___         _                 _      
|  \/  |        | |               ( )     
| .  . | ___  __| |_   _ ___  __ _|/ ___  
| |\/| |/ _ \/ _' | | | / __|/ _' | / __| 
| |  | |  __/ (_| | |_| \__ \ (_| | \__ \ 
\_|  |_/\___|\__,_|\__,_|___/\__,_| |___/ 
                                                                           
   _____                  __                
  |  _  |                / _|               
  | | | |_   _  ___  ___| |_                
  | | | | | | |/ _ \/ _ \  _|               
  \ \/' / |_| |  __/  __/ |                 
   \_/\_\__,_|\___|\___|_|                            

 An homage to Sektor7's Perun's Fart
  
 credit: @SEKTOR7net @MalDevAcademy
  
        by assume-breach"

}

title
echo -e $BOLD_CYAN
echo "Choose an option:"
echo ""
echo -e "$BOLD_BLUE 1.$BOLD_WHITE Create EXE"
echo -e "$BOLD_BLUE 2.$BOLD_WHITE Create DLL"
echo ""
echo -n -e "$BOLD_WHITE >"
read CHOICE
clear

if [ $CHOICE == 1 ]; then
	echo ""
	bash EXE/medusa.sh

elif [ $CHOICE == 2 ]; then
	echo ""
	bash DLL/medusa.sh

else
	echo -e $BOLD_RED Invalid option
	sleep 3
	trap easyexit EXIT
fi
