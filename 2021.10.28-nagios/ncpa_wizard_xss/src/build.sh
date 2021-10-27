#!/bin/bash -e

# Global variables
UNAME=$(uname)
if [ "$UNAME" == "Darwin" ] || [ "$UNAME" == "AIX" ] || [ "$UNAME" == "SunOS" ]; then
    BUILD_DIR=$( cd "$(dirname "$0")" ; pwd -P )
    AGENT_DIR="$BUILD_DIR/../agent"
else
    BUILD_DIR=$(dirname "$(readlink -f "$0")")
    AGENT_DIR=$(readlink -f "$BUILD_DIR/../agent")
fi
NCPA_VER=$(cat $BUILD_DIR/../VERSION)

# User-defined variables
SKIP_SETUP=0
PACKAGE_ONLY=0
BUILD_ONLY=0
BUILD_TRAVIS=0


# --------------------------
# General functions
# --------------------------


usage() {
    echo "Use the build.sh script to setup build environment, compile, "
    echo "and package builds. Works with most common linux OS."
    echo ""
    echo "Example: ./build.sh"
    echo ""
    echo "Options:"
    echo "  -h | --help         Show help/documentation"
    echo "  -S | --skip-setup   Use this option if you have manually set up"
    echo "                      the build environment (don't auto setup)"
    echo "  -p | --package-only Bundle a package only (ncpa folder must exist"
    echo "                      in the build directory)"
    echo "  -b | --build-only   Build the ncpa binaries only (do not package)"
    echo "  -T | --travis       Set up environment for Travis CI builds"
    echo "  -c | --clean        Clean up the build directory"
    echo ""
    echo "Operating Systems Supported:"
    echo " - CentOS, RHEL, Oracle, CloudLinux"
    echo " - Ubuntu, Debian"
    echo " - OpenSUSE, SLES"
    echo " - AIX *"
    echo " - Solaris *"
    echo ""
    echo "* Some systems require extra initial setup, find out more:"
    echo "https://github.com/NagiosEnterprises/ncpa/blob/master/BUILDING.rst"
    echo ""
}


clean_build_dir() {
    echo "Cleaning up build directory..."
    rm -rf $BUILD_DIR/ncpa-*
    rm -rf $AGENT_DIR/build
    rm -rf $BUILD_DIR/NCPA-INSTALL-*
    rm -f $BUILD_DIR/*.rpm $BUILD_DIR/*.dmg $BUILD_DIR/*.deb
    rm -f $BUILD_DIR/ncpa.spec
    rm -f $BUILD_DIR/*.tar.gz
    rm -rf $BUILD_ROOT
    rm -rf $BUILD_DIR/debbuild
}


# --------------------------
# Startup actions
# --------------------------


# Get the arguments passed to us

while [ -n "$1" ]; do
    case "$1" in
        -h | --help)
            usage
            exit 0
            ;;
        -c | --clean)
            clean_build_dir
            exit 0
            ;;
        -S | --skip-setup)
            SKIP_SETUP=1
            ;;
        -p | --package-only)
            PACKAGE_ONLY=1
            ;;
        -b | --build-only)
            BUILD_ONLY=1
            ;;
        -T | --travis)
            BUILD_TRAVIS=1
            ;;
    esac
    shift
done


# --------------------------
# Do initial setup
# --------------------------


# Load required things for different systems
echo "Running build for: $UNAME"
if [ "$UNAME" == "Linux" ]; then
    . $BUILD_DIR/linux/setup.sh
elif [ "$UNAME" == "SunOS" ] || [ "$UNAME" == "Solaris" ]; then
    . $BUILD_DIR/solaris/setup.sh
elif [ "$UNAME" == "AIX" ]; then
    . $BUILD_DIR/aix/setup.sh
elif [ "$UNAME" == "Darwin" ]; then
    . $BUILD_DIR/osx/setup.sh
else 
    echo "Not a supported system for our build script."
    echo "If you're sure all pre-reqs are installed, try running the"
    echo "build without setup: ./build.sh --build-only"
fi

# Check that pre-reqs have been installed
if [ $BUILD_TRAVIS -eq 0 ] && [ $PACKAGE_ONLY -eq 0 ] && [ $BUILD_ONLY -eq 0 ]; then
    if [ ! -f $BUILD_DIR/prereqs.installed ] && [ $SKIP_SETUP -eq 0 ]; then
        echo "** WARNING: This should not be done on a production system. **"
        #read -r -p "Automatically install system pre-reqs? [Y/n] " resp
	resp="yes"
        if [[ $resp =~ ^(yes|y|Y| ) ]] || [[ -z $resp ]]; then
            install_prereqs
            touch $BUILD_DIR/prereqs.installed
        fi
    fi
elif [ $BUILD_TRAVIS -eq 1 ]; then

    # Set up travis environment
    sudo useradd nagios
    cd $BUILD_DIR
    python -m pip install -r resources/require.txt --upgrade
    exit 0

fi


# Update the required python modules
cd $BUILD_DIR
echo "Updating python modules..."
update_py_packages >> $BUILD_DIR/build.log


# --------------------------
# Build
# --------------------------


# Clean build dir
clean_build_dir


# Build the python with cx_Freeze
echo "Building NCPA binaries..."
cd $BUILD_DIR
find $AGENT_DIR -name *.pyc -exec rm '{}' \;
mkdir -p $AGENT_DIR/plugins
mkdir -p $AGENT_DIR/build
mkdir -p $AGENT_DIR/var/log
cat /dev/null > $AGENT_DIR/var/log/ncpa_passive.log
cat /dev/null > $AGENT_DIR/var/log/ncpa_listener.log

(
    cd $AGENT_DIR
    $PYTHONBIN setup_posix.py build_exe > $BUILD_DIR/build.log

    # Move the ncpa binary data
    cd $BUILD_DIR
    rm -rf $BUILD_DIR/ncpa
    cp -rf $AGENT_DIR/build/exe.* $BUILD_DIR/ncpa

    # REMOVE LIBFFI COPY - PLEASE CHANGE THIS LATER
    # It should be in .libs_cffi_backend for proper linking and
    # possibly in the future we will fix this but we have to include
    # the exact version ... this will delete the duplicate which should
    # have a special name like libffi-6322464e.so.6.0.4
    rm -f $BUILD_DIR/ncpa/libffi-*.so.*

    # Set permissions
    chmod -R g+r $BUILD_DIR/ncpa
    chmod -R a+r $BUILD_DIR/ncpa
    chown nagios:nagios $BUILD_DIR/ncpa/var
    chown nagios:nagios $BUILD_DIR/ncpa/etc $BUILD_DIR/ncpa/etc/*.cfg*
    chown nagios:nagios $BUILD_DIR/ncpa/etc/ncpa.cfg.d $BUILD_DIR/ncpa/etc/ncpa.cfg.d/*
    chmod 755 $BUILD_DIR/ncpa/etc $BUILD_DIR/ncpa/etc/ncpa.cfg.d
    chmod 755 $BUILD_DIR/ncpa/var
    chmod 755 $BUILD_DIR/ncpa

    # Build tarball
    cp -rf ncpa ncpa-$NCPA_VER
    if [ "$UNAME" == "AIX" ]; then
        tar cvf ncpa-$NCPA_VER.tar ncpa-$NCPA_VER >> $BUILD_DIR/build.log
        gzip -f ncpa-$NCPA_VER.tar >> $BUILD_DIR/build.log
    elif [ "$UNAME" == "Linux" ]; then
        tar -czvf ncpa-$NCPA_VER.tar.gz ncpa-$NCPA_VER >> $BUILD_DIR/build.log
    fi
)


# --------------------------
# Package
# --------------------------


if [ $BUILD_ONLY -eq 0 ]; then

    # Build package based on system
    echo "Packaging for system type..."

    if [ "$UNAME" == "Linux" ]; then
        linux/package.sh
    elif [ "$UNAME" == "SunOS" ] || [ "$UNAME" == "Solaris" ]; then
        solaris/package.sh
    elif [ "$UNAME" == "AIX" ]; then
        aix/package.sh
    elif [ "$UNAME" == "Darwin" ]; then
        osx/package.sh
    else
        echo "No packaging method exists. You can locate binaries here:"
        echo "$BUILD_DIR/ncpa"
    fi

    # Remove the build directory and tar.gz
    cd $BUILD_DIR
    rm -rf *.tar.gz
    rm -rf ncpa-$NCPA_VER

fi
