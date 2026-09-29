# BASE_IMAGE has intentionally no default.  supply a verified image that is
# already present in local storage and contains python >=3.11 plus pytest.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

LABEL org.opencontainers.image.title="umzug offline smoke tests"
LABEL org.opencontainers.image.description="Networkless, unprivileged parser/planner/unit-test harness; not a hardware-hardening proof"

WORKDIR /work
COPY . /work

ENV HOME=/tmp/umzug-home \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_INDEX=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

USER 65532:65532
ENTRYPOINT ["python3", "-m", "pytest"]
CMD ["-q", "-p", "no:cacheprovider"]
