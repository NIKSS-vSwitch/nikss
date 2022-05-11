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

5. cmake options:

   There is a single option to the cmake command, which will change how psabpf
   is built to generate a shared library in addition to the psabpf-ctl CLI.
   This will also allow other programs to link against the libpsabpf shared
   library. To use this option, run the cmake command as below:

   ```shell
   cmake -DBUILD_SHARED=on ..
   ```

   If you have built with the shared library on, you will want to ensure to add
   /usr/local/lib to your shared library path, something like the following
   will work:

   ```shell
   export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
   ```

Note that `psabpf-ctl` is statically linked with shipped `libbpf`, so there is no need to install this library system-wide.
