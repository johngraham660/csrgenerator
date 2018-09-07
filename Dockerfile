FROM jazzdd/alpine-flask:latest
LABEL maintainer="David Wittman"

# Install deps before we add our project to cache this layer
RUN apk add --no-cache gcc python-dev musl-dev libffi-dev openssl openssl-dev

# Adding requirements.txt file here so we can cache the pip install layer as well
ADD ./requirements.txt /app/

RUN pip install -r requirements.txt && \
    apk del gcc git python-dev musl-dev libffi-dev openssl-dev

# Now add everything into the container
ADD  . /app/
