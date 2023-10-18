### Requirements

- Docker, Docker Compose (only if building with docker, see below)
- Java JDK 17+
- Gradle

# Docker

### Requirements

- Docker
- Docker Compose v2
- A network connection on the build machine

```
git clone https://github.com/foundryzero/ghidra-deep-links.git
cd ghidra-deep-links
GHIDRA_VERSION=10.3.3 docker compose up --exit-code-from build.service
```

Prior to ghidra 10.3.2, ghidra plugins needed to be built against each new release of ghidra in order to be compatible. As of 10.3.2 it is possible to bypass the compatibility check, but it is still advisable to build the plugin for each specific version. To build for a different ghidra version, edit the `GHIDRA_VERSION` environment variable.

# Manual

### Requirements

- Java JDK 17+
- Gradle
- Ghidra (of the version you're building against)

```
git clone https://github.com/foundryzero/ghidra-deep-links.git
cd ghidra-deep-links/extension
gradle -PGHIDRA_INSTALL_DIR=/path/to/ghidra/install
```

However you build, the built extension will be placed in `dist/` in the source directory.

