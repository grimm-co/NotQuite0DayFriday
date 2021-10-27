#!/bin/bash

# Globals
PYTHONVERSION="2.7.18"
PYTHONTAR="Python-$PYTHONVERSION"
PYTHONVER="python2.7"
CXFREEZEVER="cx_Freeze-4.3.4"
SKIP_PYTHON=0

# Get information about system
. $BUILD_DIR/linux/init.sh

update_py_packages() {
    PYTHONBIN=$(which python2.7)
    resources="require.txt"
    if [ "$dist" == "el6" ] || [ "$dist" == "el7" ] || [ "$dist" == "debian8" ]; then
        resources="require.dep.txt"
    fi

    LDFLAGS='-Wl,-rpath,\${ORIGIN} -Wl,-rpath,\${ORIGIN}/lib' $PYTHONBIN -m pip install -r $BUILD_DIR/resources/$resources --upgrade --no-binary :all:
}

install_prereqs() {


    # --------------------------
    #  INSTALL SYSTEM REQS
    # --------------------------


    if [ "$distro" == "Debian" ] || [ "$distro" == "Ubuntu" ]; then

        apt-get install debian-builder rpm gcc g++ wget openssl libssl-dev libffi-dev sqlite3 libsqlite3-dev zlib1g-dev alien -y

    elif [ "$distro" == "CentOS" ] || [ "$distro" == "RHEL" ] || [ "$distro" == "Oracle" ] || [ "$distro" == "CloudLinux" ]; then

        yum install epel-release -y
        yum install gcc gcc-c++ zlib zlib-devel openssl openssl-devel rpm-build libffi-devel sqlite sqlite-devel wget make -y

    elif [ "$distro" == "SUSE LINUX" ] || [ "$distro" == "SLES" ] || [ "$distro" == "OpenSUSE" ]; then

        # We don't need to install python on SLES due to their updated version of python
        # available with the OS itself
        if [ "$dist" == "sles15" ] || [ "$dist" == "sles12" ] || [ "$distro" == "OpenSUSE" ]; then

            zypper install gcc gcc-c++ zlib zlib-devel openssl libopenssl-devel sqlite3 sqlite3-devel libffi-devel rpm-build wget

        elif [ "$dist" == "sles11" ]; then

            # Show information about suse manual config for SDK
            echo ""
            echo "Manual configuration required:"
            echo ""
            echo "1. Register your SUSE system."
            echo "2. Install SDK repo:"
            echo "   https://www.suse.com/support/kb/doc/?id=7015337"
            if [ "$arch" == "i686" ]; then
                arch="i586";
            fi
            echo "   https://nu.novell.com/repo/\$RCE/SLE11-SDK-SP4-Pool/sle-11-$arch/rpm/$arch/sle-sdk-release-11.4-1.55.$arch.rpm"
            echo "   https://nu.novell.com/repo/\$RCE/SLE11-SDK-SP4-Pool/sle-11-$arch/rpm/$arch/sle-sdk-release-SDK-11.4-1.55.$arch.rpm"
            echo "3. Install the Security Module:"
            echo "   https://www.suse.com/documentation/suse-best-practices/singlehtml/securitymodule/securitymodule.html"
            echo ""
            echo "Press enter to continue..."
            read

            # Install base packages
            zypper install gcc gcc-c++ zlib zlib-devel sqlite3 sqlite3-devel rpm wget libffi-devel

            # Install openssl 1.0.x for TLS 1.2 support
            zypper install openssl1 libopenssl1_0_0 libopenssl1-devel libcurl4-openssl1 curl-openssl1 wget-openssl1

        fi

    elif [ "$distro" == "Raspbian" ]; then

        apt-get install gcc openssl sqlite3 libsqlite3-dev libffi-dev rpm git debian-builder alien libssl-dev -y

    else

        echo "Could not determine your OS type... you need to install the following dependencies:"
        echo ""
        echo "gcc, gcc-c++"
        echo "zlib, zlib-devel"
        echo "openssl, openssl-devel"
        echo "sqlite3, sqlite3-devel"
        echo "libffi-devel"
        echo "rpm-build"
        echo "wget"
        echo "git"
        echo ""
        echo "If you're running a debian distro you must also install debian-builder"
        echo ""
        exit 1

    fi


    # --------------------------
    #  INSTALL SOURCE FILES
    # --------------------------


    cd $BUILD_DIR/resources

    # Install bundled Python version from source
    if [ $SKIP_PYTHON -eq 0 ]; then
        if [ ! -f $PYTHONTAR.tgz ]; then
            wget https://www.python.org/ftp/python/$PYTHONVERSION/$PYTHONTAR.tgz
        fi
        tar xf $PYTHONTAR.tgz
        cd $PYTHONTAR
        ./configure LDFLAGS='-Wl,-rpath,\$${ORIGIN} -Wl,-rpath,\$${ORIGIN}/lib' && make && make altinstall
        cd ..
        rm -rf $PYTHONTAR

        PYTHONBIN=$(which python2.7)

        # Link lib-dynload from lib64 to lib due to arch issues for Python 2.7
        if [ "$dist" == "os15" ]; then
            ln -s /usr/local/lib64/python2.7/lib-dynload/ /usr/local/lib/python2.7/lib-dynload
        fi
    fi
    PYTHONBIN=$(which python2.7)

    set -x
    # Install the patched version of cx_Freeze
    tar xf $CXFREEZEVER.tar.gz
    cd $CXFREEZEVER
    $PYTHONBIN setup.py install
    cd ..
    rm -rf $CXFREEZEVER


    # --------------------------
    #  INSTALL PIP & PIP MODULES
    # --------------------------


    # Install pip
    
    #cd /tmp && wget --no-check-certificate https://raw.githubusercontent.com/pypa/get-pip/master/2.7/get-pip.py && $PYTHONBIN /tmp/get-pip.py
    cd /tmp && wget --no-check-certificate https://bootstrap.pypa.io/pip/2.7/get-pip.py && $PYTHONBIN /tmp/get-pip.py

    # Install modules
    update_py_packages


    # --------------------------
    #  MISC ADDITIONS
    # --------------------------


    set +e
    useradd nagios
    groupadd nagios
    usermod -g nagios nagios
    set -e


}
