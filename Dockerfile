FROM gradle:jdk19

RUN apt-get update && apt-get install python3-pip -y && rm -rf /var/lib/apt/lists/*
RUN bash -c "AIOHTTP_NO_EXTENSIONS=1 pip3 install pygithub"

COPY docker_build.py /docker_build.py

CMD [ "python3", "-u", "/docker_build.py" ]
