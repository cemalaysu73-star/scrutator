# Scrutator: build a wheel, install it into a slim image, run as an unprivileged user.
#   docker build -t scrutator .
#   docker run --rm scrutator --version
#   docker run --rm -v "$PWD/out:/work" scrutator scan example.com --ai off --out /work
# Not built or run on the machine this file was written on (no Docker daemon was available): CI builds it.
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip wheel --no-deps -w /wheels .

FROM python:3.12-slim
RUN useradd --create-home --shell /usr/sbin/nologin scrutator
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir "$(ls /wheels/scrutator-*.whl)[mcp]" && rm -rf /wheels
USER scrutator
WORKDIR /work
ENTRYPOINT ["scrutator"]
CMD ["--help"]
