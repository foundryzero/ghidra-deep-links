FROM gradle:jdk21

RUN apt-get update && apt-get install python3-pip -y && rm -rf /var/lib/apt/lists/*
RUN bash -c "AIOHTTP_NO_EXTENSIONS=1 pip3 install pygithub --break-system-packages"

COPY docker_build.py /docker_build.py
COPY docker_release.py /docker_release.py
