请不要删除/重命名此目录或目录下的onbuild.exe，因为项目设定了预生成事件会调用，否则将会build失败。

此目录的作用是在每一次调试或生成时自动增加项目根目录下的build_count.txt中的数字，以便统计
项目编译的次数。请不要手动运行onbuild.exe，因为那样会导致编译计数意外增加，尽管不影响项目的生成调试。

onbuild.cpp是onbuild.exe对应源码，并配有一个makefile。

使用g++编译onbuild.exe：
g++.exe onbuild.cpp -o onbuild

或者使用makefile：
mingw32-make.exe

如果已经编译，需要用makefile清除，使用：
mingw32-make.exe clean