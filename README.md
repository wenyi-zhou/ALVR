# 调试指令
```
"D:\work\alvr-pc\build\mix_streamer_windows\MIX Dashboard.exe" --control_port=31303 --media_port=31304 --boxie_index=3 --res_app="'D:\XR\VRCar\VRCar.exe'"
```


# 编译客户端
编译库：
```bash

//若报错error: could not compile `symphonia-bundle-mp3` (lib)，执行rustup update后编译；//执行cargo xtask clean，和手动删掉target目录，再编译

cargo xtask build-client-lib --no-stdcpp --release

cargo xtask build-client-lib

```

编译客户端:
```bash
cargo xtask build-client
```

# 编译PC端
目录 ALVR\build\alvr_streamer_windows\ALVR Dashboard.exe

编译
```bash
//关掉vrmonitor后，vrserver还要30秒才自动退出，会占用driver_alvr_server.dll文件编不了，所以先kill
taskkill /IM vrserver.exe /F; cargo xtask build-streamer
```

打包安装包
```bash
cargo xtask package-streamer --no-rebuild
```

重新编译
```bash
cargo xtask clean
```

HELP
```bash
cargo xtask
Developement actions for ALVR.

USAGE:
    cargo xtask <SUBCOMMAND> [FLAG] [ARGS]

SUBCOMMANDS:
    prepare-deps        Download and compile streamer and client external dependencies
    build-streamer      Build streamer, then copy binaries to build folder
    build-launcher      Build launcher, then copy binaries to build folder
    build-client        Build client, then copy binaries to build folder
    build-client-lib    Build a C-ABI ALVR client library and header.
    run-streamer        Build streamer and then open the dashboard
    run-launcher        Build launcher and then open it
    package-streamer    Build streamer with distribution profile, make archive
    package-launcher    Build launcher in release mode, make portable and installer versions
    package-client-lib  Build client library then zip it
    clean               Removes all build artifacts and dependencies.
    bump                Bump streamer and client package versions
    clippy              Show warnings for selected clippy lints
    kill-oculus         Kill all Oculus processes

FLAGS:
    --help              Print this text
    --keep-config       Preserve the configuration file between rebuilds (session.json)
    --no-nvidia         Disables nVidia support on Linux. For prepare-deps subcommand
    --release           Optimized build with less debug checks. For build subcommands
    --gpl               Bundle GPL libraries (FFmpeg). Only for Windows
    --appimage          Package as AppImage. For package-streamer subcommand
    --zsync             For --appimage, create .zsync update file and build AppImage with embedded update information. For package-streamer subcommand
    --nightly           Append nightly tag to versions. For bump subcommand
    --no-rebuild        Do not rebuild the streamer with run-streamer
    --ci                Do some CI related tweaks. Depends on the other flags and subcommand
    --no-stdcpp         Disable linking to libc++_shared with build-client-lib

ARGS:
    --platform <NAME>   Name of the platform (operative system or hardware name). snake_case
    --version <VERSION> Specify version to set with the bump-versions subcommand
    --root <PATH>       Installation root. By default no root is set and paths are calculated using
                        relative paths, which requires conforming to FHS on Linux.
```