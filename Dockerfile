FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
        libmagic1 \
        libmagic-dev \
        file \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/

RUN mkdir -p /app/staticfiles

EXPOSE $PORT

RUN echo '#!/bin/bash\n\
echo "Starting Railway deployment..."\n\
\n\
echo "Running migrations..."\n\
python manage.py migrate --settings=vast_project.railway_settings\n\
\n\
echo "Collecting static files..."\n\
python manage.py collectstatic --noinput --settings=vast_project.railway_settings\n\
\n\
echo "Starting Django server on Railway..."\n\
python manage.py runserver 0.0.0.0:$PORT --settings=vast_project.railway_settings' > /app/railway-start.sh

RUN chmod +x /app/railway-start.sh

CMD ["/app/railway-start.sh"]
