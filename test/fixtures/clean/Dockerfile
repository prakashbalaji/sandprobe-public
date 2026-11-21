# clean: a non-root agent, no capabilities, NoNewPrivs, a read-only root and no network (the run options in
# internal/host/fixtures_test.go set the last four). Nothing planted.
FROM debian:trixie-slim
RUN useradd -m -s /bin/bash agent
CMD ["sleep", "infinity"]
