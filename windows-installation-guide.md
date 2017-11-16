# Installing charm-crypto on Windows x64

## Pre-built package

The easiest way to install charm-crypto is to use the pre-built (with Mingw64) package for Windows x64.
1. Install Python 3.5 for Windows x86-64: [Python3.5_win_x86_64](https://www.python.org/ftp/python/3.5.2/python-3.5.2-amd64.exe).
(or Python 3.5 for Windows x86: [Python3.5_win_x86](https://www.python.org/ftp/python/3.5.2/python-3.5.2.exe)).

2. Extract `charm-crypto-win-x64.7z` (or `charm-crypto-win32.7z` for Python 32-bit) and go to `charm-crypto` folder

3. Copy all `.dll` files to `C:\Windows\System32`.

4. Run the following to install Charm-crypto for Python 64-bit:
    ```
    easy_install Charm_Crypto-0.43-py3.5-win-amd64.egg
    ```
or for Python 32-bit:

    easy_install Charm_Crypto-0.43-py3.5-win32.egg
    
## Manual build and installation of charm-crypto using Mingw32 and Python 32-bit

If the pre-built packages (see above) doesn't work or not appropriate for some reasons, then please find detailed steps on how to build charm-crypto on Win32 using Mingw32:

1. Install and prepare mingw32
    1. Install MSYS2 [MSYS2_32_installer](http://repo.msys2.org/distrib/i686/msys2-i686-20161025.exe)
    2. Open MSYS2 shell (_C:\msys32\msys2.exe_)
    3. Update packages (from MSYS2 shell):
    
         ```
         pacman -Sy pacman
         pacman -Syu
         pacman -Su
         ```
    4. Install a Mingw32 toolchain (from MSYS2 shell):
    
         ```
         pacman -S mingw-w64-i686-gcc
         pacman -S make
         ```
2. Install charm-crypto dependencies (from MSYS2 shell):
    1. Open MSYS2 shell (_C:\msys32\msys2.exe_)
    2. Install bison `pacman -S bison`
    3. Install openssl-dev `pacman -S openssl-devel`
    4. Install gmp-dev `pacman -S gmp-devel`
 
3. Build PBC lib (charm-crypto dependency)
    1. Get and extract pbc source [PBC](https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz)
    2. Open Mingw32 shell (_C:\msys32\mingw32.exe_)
    3. Go to extracted PBC location
    4. Build PBC:
    
        ```
         ./configure --prefix=/mingw32 --disable-static --enable-shared
         make
         make install
        ``` 

4. Add mingw32/bin (_C:\msys32\mingw32\bin_) to PATH
         
5. Install Python 3.5 for Windows 32 bit: [Python3.5_win_x86](https://www.python.org/ftp/python/3.5.2/python-3.5.2.exe). 
   In what follows we assume that it was installed to _C:\Users\user\AppData\Local\Application Data\Programs\Python\Python35-32_. 

6. Patch Python to be able to work with Mingw32
    1. Patch the cygwin compiler in distutils:
        1. Open _C:\Users\indy\AppData\Local\Application Data\Programs\Python\Python35-32\Lib\distutils\cygwinccompiler.py_
        2. Comment out all lines with `get_msvcr()` call.
    
7. Build charm-crypto
    1. Get and extract charm-crypto source [charm-crypto-0.43](https://pypi.python.org/packages/2b/6b/2c2abcb66f62155a60f5ecfe6936f651ecb9a115a2203c1b1d60d0e8d15e/Charm-Crypto-0.43.tar.gz#md5=eaba7346c6ac50079a4b7f75f5ce644d)
    2. Go to extracted charm-crypto folder
    3. Add `#include <stdint.h>` at the top of the following files:
    
        ```
        Charm-Crypto-0.43\charm\core\math\integer\integermodule.h
        Charm-Crypto-0.43\charm\core\math\elliptic_curve\ecmodule.h
        Charm-Crypto-0.43\charm\core\math\pairing\pairingmodule.h
        ```
    4. Open Mingw32 shell (_C:\msys32\mingw32.exe_)
    5. Build charm-crypto (please note that we specify the path to python35.exe there)
    
        ```
         ./configure.sh --prefix=/mingw32 --python=/c/users/user/AppData/Local/Programs/Python/Python35-32/python.exe 
         make
         make install
        ```         

## Manual build and installation of charm-crypto using Mingw64 and Python 64-bit

If the pre-built packages (see above) doesn't work or not appropriate for some reasons, then please find detailed steps on how to build charm-crypto on Win_x64 using Mingw64:

1. Install and prepare mingw64
    1. Install MSYS2 [MSYS2_64_installer](http://repo.msys2.org/distrib/x86_64/msys2-x86_64-20161025.exe)
    2. Open MSYS2 shell (_C:\msys64\msys2.exe_)
    3. Update packages (from MSYS2 shell):
    
         ```
         pacman -Sy pacman
         pacman -Syu
         pacman -Su
         ```
    4. Install a Mingw64 toolchain (from MSYS2 shell):
    
         ```
         pacman -S mingw-w64-x86_64-gcc
         pacman -S make
         ```
2. Install charm-crypto dependencies (from MSYS2 shell):
    1. Open MSYS2 shell (_C:\msys64\msys2.exe_)
    2. Install bison `pacman -S bison`
    3. Install openssl-dev `pacman -S openssl-devel`
    4. Install gmp-dev `pacman -S gmp-devel`
 
3. Build PBC lib (charm-crypto dependency)
    1. Get and extract pbc source [PBC](https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz)
    2. Open Mingw64 shell (_C:\msys64\mingw64.exe_)
    3. Go to extracted PBC location
    4. Build PBC:
    
        ```
         ./configure --prefix=/mingw64 --disable-static --enable-shared
         make
         make install
        ``` 

4. Add mingw64/bin (_C:\msys64\mingw64\bin_) to PATH
         
5. Install Python 3.5 for Windows x86-64: [Python3.5_win_x86_64](https://www.python.org/ftp/python/3.5.2/python-3.5.2-amd64.exe). 
   In what follows we assume that it was installed to _C:\Users\user\AppData\Local\Application Data\Programs\Python\Python35_. 

6. Patch Python to be able to build and use 64 bit binaries
    1. Download and extract gendef.exe from [gendef](https://sourceforge.net/projects/mingw/files/MinGW/Extension/gendef/gendef-1.0.1346/gendef-1.0.1346-1-mingw32-bin.tar.lzma/download)
    2. Copy dendef.exe into mingw64/bin (_C:\msys64\mingw64/bin_)
    3. Copy _python35.dll_ to _libs_ folder:
    
        ```
        cd C:\Users\user\AppData\Local\Application Data\Programs\Python\Python35
        cp python35.dll libs
        ```
    4. Patch _libpython35.a_
    
        ```
        cd C:\Users\user\AppData\Local\Application Data\Programs\Python\Python35\libs
        rename python35.lib old_python35.lib
        gendef python35.dll
        dlltool --dllname python35.dll --def python35.def --output-lib libpython35.a
        ```
    5. Patch _pyconfig.h_:
        1. Open _C:\Users\user\AppData\Local\Application Data\Programs\Python\Python35\include\pyconfig.h_
        2. In that file search for the text `#ifdef _WIN64`, and cut out the following three lines:
        
            ```
            #ifdef _WIN64
            #define MS_WIN64
            #endif
            ```
        3. Search for the text `#ifdef _MSC_VER`. Paste in the cut-out lines, ABOVE the `#ifdef _MSC_VER`.
    6. Patch the cygwin compiler in distutils:
        1. Open _C:\Users\user\AppData\Local\Application Data\Programs\Python\Python35\Lib\distutils\cygwinccompiler.py_
        2. Comment out all lines with `get_msvcr()` call.
    
7. Build charm-crypto
    1. Get and extract charm-crypto source [charm-crypto-0.43](https://pypi.python.org/packages/2b/6b/2c2abcb66f62155a60f5ecfe6936f651ecb9a115a2203c1b1d60d0e8d15e/Charm-Crypto-0.43.tar.gz#md5=eaba7346c6ac50079a4b7f75f5ce644d)
    2. Go to extracted charm-crypto folder
    3. Add `#include <stdint.h>` at the top of the following files:
    
        ```
        Charm-Crypto-0.43\charm\core\math\integer\integermodule.h
        Charm-Crypto-0.43\charm\core\math\elliptic_curve\ecmodule.h
        Charm-Crypto-0.43\charm\core\math\pairing\pairingmodule.h
        ```
    4. Open Mingw64 shell (_C:\msys64\mingw64.exe_)
    5. Build charm-crypto (please note that we specify the path to python35.exe there)
    
        ```
         ./configure.sh --prefix=/mingw64 --python=/c/users/user/AppData/Local/Programs/Python/Python35/python.exe 
         make
         make install
        ``` 
