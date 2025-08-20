from docker.io/rein1605/agent-sentinel:v4

RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

cmd ["python", "server.py"]
