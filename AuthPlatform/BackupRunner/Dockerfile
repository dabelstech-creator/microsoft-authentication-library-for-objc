FROM postgres:18-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-requests gnupg ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /backup
COPY AuthPlatform/BackupRunner/backup_once.py /backup/backup_once.py

USER postgres
ENTRYPOINT ["python3", "/backup/backup_once.py"]
