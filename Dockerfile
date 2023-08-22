FROM python:3-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY updatedns.py ./
CMD [ "python", "./updatedns.py", "--server", "--verbose" ]