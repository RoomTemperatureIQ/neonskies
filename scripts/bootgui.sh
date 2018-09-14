#!/bin/bash
# Call with either 'enable' or 'disable' as first parameter

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
