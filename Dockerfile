FROM python:3.9-alpine

WORKDIR /app

# Install deps before we add our project to cache this layer
RUN apk add --no-cache gcc musl-dev libffi-dev openssl openssl-dev

# Adding requirements.txt file here so we can cache the pip install layer as well
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt && \
    apk del gcc musl-dev libffi-dev openssl-dev

# Now add everything into the container
COPY . .

EXPOSE 5555

CMD ["python", "app.py"]
