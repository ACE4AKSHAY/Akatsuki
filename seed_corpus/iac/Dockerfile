# EXPECTED_FINDINGS: [{"primitive":"pyca/cryptography","category":"key-management","line":3},{"primitive":"node-forge","category":"key-management","line":4}]
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y openssl
RUN pip install pyca/cryptography
RUN npm install node-forge
