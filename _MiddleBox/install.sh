#!/bin/sh
apt-get install bison << EF
y
EF
apt-get install g++ << EF
y
EF
apt-get install make
apt-get install flex << EF
y
EF
wget http://www.tcpdump.org/release/libpcap-1.7.4.tar.gz
tar -zxvf libpcap-1.7.4.tar.gz
rm libpcap-1.7.4.tar.gz
cd libpcap-1.7.4/
./configure
make
make install
cd ..
wget http://ufpr.dl.sourceforge.net/project/boost/boost/1.58.0/boost_1_58_0.tar.gz
tar -zxvf boost_1_58_0.tar.gz
rm boost_1_58_0.tar.gz
chmod 777 boost_1_58_0/
apt-get install libssl-dev << EF
y
EF
wget http://www.netfilter.org/projects/libnfnetlink/files/libnfnetlink-1.0.1.tar.bz2
tar --bzip2 -xf libnfnetlink-1.0.1.tar.bz2
rm libnfnetlink-1.0.1.tar.bz2
cd libnfnetlink-1.0.1/
./configure
make
make install
cd ..
apt-get install pkg-config
wget http://www.netfilter.org/projects/libmnl/files/libmnl-1.0.3.tar.bz2
tar --bzip2 -xf libmnl-1.0.3.tar.bz2
rm libmnl-1.0.3.tar.bz2
cd libmnl-1.0.3/
./configure
make
make install
cd ..
wget http://www.netfilter.org/projects/libnetfilter_queue/files/libnetfilter_queue-1.0.2.tar.bz2
tar --bzip2 -xf libnetfilter_queue-1.0.2.tar.bz2
rm libnetfilter_queue-1.0.2.tar.bz2
cd libnetfilter_queue-1.0.2/
./configure
make
make install
cd ..
apt-get install libglib2.0-dev << EF
y
EF
wget https://ftp.gnu.org/gnu/gmp/gmp-6.0.0a.tar.bz2
tar --bzip2 -xf gmp-6.0.0a.tar.bz2
rm gmp-6.0.0a.tar.bz2
cd gmp-6.0.0/
./configure
make
make install
cd ..
wget http://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
tar -zxvf pbc-0.5.14.tar.gz
rm pbc-0.5.14.tar.gz
cd pbc-0.5.14/
./configure
make
make install
cd ..
wget http://acsc.cs.utexas.edu/cpabe/libbswabe-0.9.tar.gz
tar -zxvf libbswabe-0.9.tar.gz
rm libbswabe-0.9.tar.gz
cd libbswabe-0.9/
./configure
make
make install
cd ..
apt-get install vim << EF
y
EF
