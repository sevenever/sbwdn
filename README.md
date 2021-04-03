# sbwdn
穷玩车富玩表傻逼玩电脑


# cross compile for openwrt:

export STAGING_DIR=\<your staging dir\>
export PATH=${PATH}:${STAGING_DIR}/bin

export STAGING_DIR=/home/xxxx/git/openwrt/openwrt/staging_dir/toolchain-mips_34kc_gcc-4.8-linaro_uClibc-0.9.33.2
export PATH=${PATH}:${STAGING_DIR}/bin

see https://openwrt.org/docs/guide-developer/crosscompile for more info

## compile libevent:

make package/libevent2/compile

## compile libconfuse:

since libconfuse is not a openwrt package, we need to download source from https://github.com/martinh/libconfuse#download then
./configure --host=mips-openwrt-linux

then

make

## compile sbwdn:

make CC=${STAGING_DIR}/bin/mips-openwrt-linux-uclibc-gcc CFLAGS='--std=gnu99 -I${STAGING_DIR}/../target-mips_34kc_uClibc-0.9.33.2/usr/include -I\<source dir of downloaded libconfuse\>/src' LFLAGS='-L${STAGING_DIR}/../target-mips_34kc_uClibc-0.9.33.2/usr/lib -L\<source dir of downloaded libconfuse\>/src/.libs'

this will create a binary that dynamically linked with libevent and libconfuse.

I ran the link command with "-levent -lconfuse" replaced with "-l:libevent.a -l:libconfuse.a" to get a static linked bin.
