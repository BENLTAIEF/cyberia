docker build -t epssapijson:latest .

docker run --rm -v D:\work\github\data\epss\csv:/data epssapijson:latest