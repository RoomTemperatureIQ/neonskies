#!/bin/bash
# Call with either 'enable' or 'disable' as first parameter

# systemctl get-default

# https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/system_administrators_guide/sect-managing_services_with_systemd-targets  
# Runlevel	Target Units	               Description
# 0 	runlevel0.target, poweroff.target      Shut down and power off the system.  
# 1 	runlevel1.target, rescue.target        Set up a rescue shell.  
# 2 	runlevel2.target, multi-user.target    Set up a non-graphical multi-user system.  
# 3 	runlevel3.target, multi-user.target    Set up a non-graphical multi-user system.  
# 4 	runlevel4.target, multi-user.target    Set up a non-graphical multi-user system.  
# 5 	runlevel5.target, graphical.target     Set up a graphical multi-user system.  
# 6 	runlevel6.target, reboot.target        Shut down and reboot the system.  

if [ "$1" == 'enable' ] ; then

    echo "setting default to 'graphical.target'"
    sudo systemctl set-default graphical.target --force 2>&1

    echo "enabling 'graphical.target'"
    sudo systemctl "$1" graphical.target --force 2>&1

    echo "enabling 'lightdm.service'"
    sudo systemctl "$1" lightdm.service --force 2>&1

    echo "reconfiguring lightdm.service"
    sudo dpkg-reconfigure lightdm 2>&1

    echo "setting lightdm defaults"
    sudo update-rc.d lightdm defaults 2>&1

elif [ "$1" == 'disable' ] ; then

    echo "setting default to 'multi-user.target'"
    sudo systemctl set-default multi-user.target --force 2>&1

    echo "disabling 'graphical.target'"
    sudo systemctl "$1" graphical.target --force 2>&1

    echo "disabling 'lightdm.server'"
    sudo systemctl "$1" lightdm.service --force 2>&1

else

    echo "Call with either \"enable\" or \"disable\" as first parameter" 2>&1

fi
