1. Make sure you have installed dependencies:
   ```shell
   sudo apt install iproute2 make cmake gcc git libgmp-dev libelf-dev zlib1g-dev libjansson-dev
   ```
2. Get the code with submodules:
   ```shell
   git clone --recursive https://github.com/P4-Research/psabpf.git
   cd psabpf
   ```
3. Build dependencies:
   ```shell
   ./build_libbpf.sh
   ```
4. Build the code and install binary file:
   To build a static psabpf-ctl binary:
   ```shell
   mkdir build
   cd build
   cmake ..
   make -j4
   sudo make install
   ```

   To build a shared library which the psabpf-ctl binary will link against:

   ```shell
   mkdir build
   cd build
   cmake -DBUILD_SHARED=on ..
   make -j4
   sudo make install
   ```

   Make sure to add /usr/local/lib to your shared library path, something like
   the following will work:

   Make sure to add /usr/local/lib to your shared library path. You can do this
   by adding this to your .bashrc:

   ```shell
   export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
   ```

Note that `psabpf-ctl` is statically linked with shipped `libbpf`, so there is no need to install this library system-wide.
