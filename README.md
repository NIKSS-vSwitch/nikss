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
   ```shell
   mkdir build
   cd build
   cmake ..
   make -j4
   sudo make install
   ```

Note that `psabpf-ctl` is statically linked with shipped `libbpf`, so there is no need to install this library system-wide.
