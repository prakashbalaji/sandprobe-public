FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements.lock /opt/sandprobe/requirements.lock
RUN pip install --no-cache-dir --require-hashes -r /opt/sandprobe/requirements.lock
COPY task.py coding.py project_exec.py checks.py receiver.py execute.py worker.py /opt/sandprobe/
RUN printf synthetic-not-a-secret >/opt/sandprobe/protected-marker && chmod 0400 /opt/sandprobe/protected-marker
RUN install -d -o 0 -g 0 -m 0555 /opt/sandprobe/home
USER 10001:10001
WORKDIR /workspace
ENTRYPOINT ["python", "-I", "/opt/sandprobe/task.py"]
