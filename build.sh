docker buildx create --name builder
docker buildx use builder
docker buildx build --platform linux/arm64 -f Dockerfile -t agent-sentinel:v3-arm . --load
docker buildx build --platform linux/amd64 -f Dockerfile -t agent-sentinel:v3-amd . --load
docker buildx build --push --platform linux/arm64,linux/amd64 -t rein1605/agent-sentinel:v3 .
