# blockchain-kotlin-tutorial

kotlin version of http://adilmoujahid.com/posts/2018/03/intro-blockchain-bitcoin-python/

Tools used:
- [kotlin](https://kotlinlang.org/)
- [vert.x-Web](https://vertx.io/docs/vertx-web/kotlin/)

## blockchain_client

Run it with the following steps:
1. gradle shadowjar
1. java -jar build/libs/blockchain_client-0.0.1-fat.jar
1. go to "http://localhost:8080/"

## blockchain

Run it with the following steps:
1. gradle shadowjar
1. java -jar build/libs/blockchain-0.0.1-fat.jar
1. go to "http://localhost:5000/"

Also, you can run it with a different port with this command:

~~~
java -jar -Dport=your-port build/libs/blockchain-0.0.1-fat.jar
~~~