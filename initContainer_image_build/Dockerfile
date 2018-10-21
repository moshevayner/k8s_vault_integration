FROM python:2.7.13-alpine
RUN pip install requests
COPY entrypoint.py /usr/bin/entrypoint.py
ENTRYPOINT ["python", "/usr/bin/entrypoint.py"]
