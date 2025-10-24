#!/usr/bin/env bash
# exit on error
set -o errexit

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Collect static files
python manage.py collectstatic --no-input --settings=vast_project.render_settings

# Run database migrations
python manage.py migrate --settings=vast_project.render_settings
