#!/bin/bash

CURPATH=$(pwd)
BH_PATH="/opt/bloodhound"
SLIVER_PATH="/opt/sliver"
HAVOC_PATH="/opt/havoc"
NGINX_PATH="/opt/nginx"
ARTIFACTS_PATH="/opt/artifacts"

prereq(){
# Prerequisites
    sudo apt update
    sudo apt install -y terminator neo4j golang-go docker.io
    sudo apt install -y git build-essential apt-utils cmake libfontconfig1 libglu1-mesa-dev libgtest-dev libspdlog-dev libboost-all-dev libncurses5-dev libgdbm-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev libbz2-dev mesa-common-dev qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools libqt5websockets5 libqt5websockets5-dev qtdeclarative5-dev golang-go qtbase5-dev libqt5websockets5-dev libspdlog-dev python3-dev libboost-all-dev mingw-w64 nasm
    sudo systemctl enable docker --now
}

bh() {
    # Download BloodHound with ADCS support
    sudo mkdir -p $BH_PATH
    sudo chown $USER:$USER $BH_PATH
    wget https://github.com/ly4k/BloodHound/releases/latest/download/BloodHound-linux-x64.zip -O $BH_PATH/BloodHound-linux-x64.zip
    unzip "$BH_PATH/BloodHound-linux-x64.zip" -d $BH_PATH
}

sliver(){
    # Download Sliver
    sudo mkdir -p $SLIVER_PATH
    sudo chown $USER:$USER $SLIVER_PATH
    wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux -O $SLIVER_PATH/sliver-server_linux
    chmod +x $SLIVER_PATH/sliver-server_linux
    sudo mkdir -p $SLIVER_PATH/payloads
    sudo chown $USER:$USER $SLIVER_PATH/payloads
}

havoc(){
    sudo mkdir -p $HAVOC_PATH
    sudo chown $USER:$USER $HAVOC_PATH
    git clone https://github.com/HavocFramework/Havoc.git $HAVOC_PATH
    git checkout dev
    cd $HAVOC_PATH/Client
    make && chmod +x Havoc
    cd $HAVOC_PATH/Teamserver
    go mod download golang.org/x/sys
    go mod download github.com/ugorji/go
    bash ./Install.sh
    make
    cd $CURPATH
}

nginx(){
    sudo mkdir -p $NGINX_PATH
    sudo chown $USER:$USER $NGINX_PATH
    cp -r /mnt/hgfs/Private/OSEP/c2/nginx $NGINX_PATH
}

artifacts() {
    sudo mkdir -p $ARTIFACTS_PATH
    sudo chown $USER:$USER $ARTIFACTS_PATH
    # SharpCollection
    git clone https://github.com/Flangvik/SharpCollection.git $ARTIFACTS_PATH/SharpCollection
    # doctrack
    git clone https://github.com/wavvs/doctrack $ARTIFACTS_PATH/doctrack
    cd $ARTIFACTS_PATH/doctrack
    dotnet publish -r win-x64 -c Release /p:PublishSingleFile=true
    dotnet publish -r linux-x64 -c Release /p:PublishSingleFile=true
    cp $ARTIFACTS_PATH/doctrack/doctrack/bin/Release/net6.0/linux-x64/publish/doctrack $ARTIFACTS_PATH/doctrack-lnx
    cp $ARTIFACTS_PATH/doctrack/doctrack/bin/Release/net6.0/win-x64/publish/doctrack.exe $ARTIFACTS_PATH/doctrack-wnd.exe
    rm -rf $ARTIFACTS_PATH/doctrack
    cd $CURPATH
    # chisel
    wget https://github.com/jpillora/chisel/releases/latest/download/chisel_1.8.1_linux_amd64.gz -O $ARTIFACTS_PATH/chisel-lnx.gz
    cd $ARTIFACTS_PATH
    gzip -d chisel-lnx.gz && chmod +x chisel-lnx
    wget https://github.com/jpillora/chisel/releases/latest/download/chisel_1.8.1_windows_amd64.gz -O $ARTIFACTS_PATH/chisel-wnd.gz
    gzip -d chisel-wnd.gz && mv chisel-wnd chisel-wnd.exe
    cd $CURPATH
    # wiretap
    wget https://github.com/sandialabs/wiretap/releases/latest/download/wiretap_0.2.1_linux_amd64.tar.gz -O $ARTIFACTS_PATH/wiretap-lnx.tar.gz
    tar -xf $ARTIFACTS_PATH/wiretap-lnx.tar.gz -C $ARTIFACTS_PATH && mv $ARTIFACTS_PATH/wiretap $ARTIFACTS_PATH/wiretap-lnx
    chmod +x $ARTIFACTS_PATH/wiretap-lnx
    rm $ARTIFACTS_PATH/wiretap-lnx.tar.gz
    wget https://github.com/sandialabs/wiretap/releases/latest/download/wiretap_0.2.1_windows_amd64.tar.gz -O $ARTIFACTS_PATH/wiretap-wnd.tar.gz
    tar -xf $ARTIFACTS_PATH/wiretap-wnd.tar.gz -C $ARTIFACTS_PATH && mv $ARTIFACTS_PATH/wiretap.exe $ARTIFACTS_PATH/wiretap-wnd.exe
    rm $ARTIFACTS_PATH/wiretap-wnd.tar.gz
}

all() {
    prereq
    bh
    sliver
    havoc
    nginx
    artifacts
}

"$@"