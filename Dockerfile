# The probe the tenant file-secrets drill deploys.
#
# A non-root numeric user on purpose: the platform owns a secret file by the
# image's declared user (root when it declares none), so running as root could
# not tell "owned by the image user" apart from "owned by root". A numeric uid
# needs no /etc/passwd entry in the guest.
FROM python:3.12-alpine

COPY app.py /app.py

USER 10001:10001

# Declared for readers; the platform routes by the manifest's
# `[[runtime.ports]]`, which is the only port declaration it reads.
EXPOSE 8080

CMD ["python", "-u", "/app.py"]
