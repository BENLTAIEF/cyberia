docker build -t nvdapijson:latest .

docker run --rm -e NVD_API_KEY="cc9cec93-88a7-4137-90db-36e4a2c57535" -e OUTPUT_DIR="/data" -e START_YEAR="2020" -e START_MONTH="1" -e SEVERITY="" -v cyberia_nvdapijson:/data nvdapijson:latest