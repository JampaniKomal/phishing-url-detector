# Phishing URL Detector with a model trained at build time.
#   docker build -t phishing-url-detector .
#   docker run --rm phishing-url-detector check "http://paypa1.com/signin"
#   docker run --rm -p 127.0.0.1:5000:5000 phishing-url-detector serve --host 0.0.0.0
FROM python:3.12-slim
WORKDIR /opt/phishing-url-detector
ENV PHISHING_URL_DETECTOR_MODELS=/opt/phishing-url-detector/models
COPY pyproject.toml README.md LICENSE ./
COPY phishing_url_detector ./phishing_url_detector
COPY data/urls.csv ./data/urls.csv
RUN pip install --no-cache-dir . \
 && phishing-url-detector -q train \
 && useradd --create-home detector
USER detector
EXPOSE 5000
ENTRYPOINT ["phishing-url-detector"]
CMD ["--help"]
