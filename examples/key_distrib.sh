for i in {0..4}
do 
    curl -X POST localhost:8080/stateful/keyrefresh -H "Content-Type: application/json" -d @6.$i.key.redistribution.json
done
    # curl -X POST localhost:8080/stateful/keyrefresh -H "Content-Type: application/json" -d @6.0.key.redistribution.json