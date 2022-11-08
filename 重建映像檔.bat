docker-compose down

docker rm $(docker ps -aq --filter name=cbdc*)

docker-compose up -d --build --force-recreate
docker-compose stop