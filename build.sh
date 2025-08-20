docker buildx create --name builder
docker buildx use builder
# docker buildx build --platform linux/arm64 -f Dockerfile -t agent-sentinel:v4-arm . --load -f Dockerfile.prebuild
# docker buildx build --platform linux/amd64 -f Dockerfile -t agent-sentinel:v4-amd . --load -f Dockerfile.prebuild
docker buildx build --push --platform linux/arm64,linux/amd64 -t rein1605/agent-sentinel:v4 . -f Dockerfile.prebuild
