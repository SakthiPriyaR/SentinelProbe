build-slim-local-images:
	@docker build -f DockerFiles/wolfi-base-Dockerfile -t sentinelprobe/sentinelprobe-base .
	# @docker build -f DockerFiles/main/cli-Dockerfile -t sentinelprobe/sentinelprobe .

build-local-image:
	@docker build -f DockerFiles/wolfi-base-Dockerfile -t sentinelprobe/sentinelprobe-base . --no-cache --progress=plain

scan-vulns:
	@trivy image sentinelprobe/sentinelprobe-base --scanners vuln

local: build-local-image scan-vulns
