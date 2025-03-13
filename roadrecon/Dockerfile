FROM python:3.11-slim AS dev
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
CMD [ "python3","/app/roadtools/roadrecon/server.py","--debug" ]

FROM python:3.11-slim AS prod
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
CMD [ "python3","/app/roadtools/roadrecon/server.py" ]