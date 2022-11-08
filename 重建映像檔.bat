docker-compose down

docker rm -f cbdc-project-bank-django-service-1
docker rm -f cbdc-project-swagger-server-1
docker rm -f cbdc-project-bank-database-service-1
docker rm -f  cbdc-project-bank-redis-service-1

docker-compose up -d --build --force-recreate
docker-compose stop