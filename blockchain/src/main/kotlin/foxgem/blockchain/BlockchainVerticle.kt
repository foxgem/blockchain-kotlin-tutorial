package foxgem.blockchain

import io.vertx.core.*
import io.vertx.core.http.HttpClientResponse
import io.vertx.core.http.HttpServerResponse
import io.vertx.core.json.JsonObject
import io.vertx.ext.web.Router
import io.vertx.ext.web.RoutingContext
import io.vertx.ext.web.handler.BodyHandler
import io.vertx.ext.web.handler.CorsHandler
import io.vertx.ext.web.handler.StaticHandler
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.util.*
import java.util.concurrent.atomic.AtomicInteger

val MINING_SENDER = "THE BLOCKCHAIN"
val MINING_REWARD = 1
val MINING_DIFFICULTY = 2

class BlockchainVerticle : AbstractVerticle() {

    val blockchain = Blockchain()

    override fun start() {
        val router = Router.router(vertx)

        router.route().handler(StaticHandler.create())
                .handler(CorsHandler.create("*")
                        .allowedHeader("Access-Control-Allow-Origin"))
        router.post().handler(BodyHandler.create())
        router.get("/configure").handler({ rc: RoutingContext -> rc.reroute("/configure.html") })
        router.get("/chain").handler(listChain)
        router.get("/transactions/get").handler(listCurrentTransactions)
        router.post("/transactions/new").handler(submitTransactions)
        router.get("/nodes/get").handler(listNodes)
        router.get("/nodes/resolve").handler(consensus)
        router.post("/nodes/register").handler(registerNode)
        router.get("/mine").handler(mine)

        vertx.createHttpServer().requestHandler({ router.accept(it) }).listen(System.getProperty("port")?.toInt() ?: 5000)
    }

    private val listChain = { rc: RoutingContext ->
        val body = JsonObject()
        body.put("chain", blockchain.chain.map { it.jsonify() })
        body.put("length", blockchain.chain.size)
        jsonResponse(rc.response(), 200, body)
    }

    private val listCurrentTransactions = { rc: RoutingContext ->
        val body = JsonObject()
        body.put("transactions", blockchain.currentTransactions.map { it.jsonify() })
        jsonResponse(rc.response(), 200, body)
    }

    private val submitTransactions = { rc: RoutingContext ->
        val request = rc.request()

        if (listOf("sender_address", "recipient_address", "amount", "signature")
                .any({ !request.formAttributes().contains(it) })) {
            textResponse(rc.response(), 400, "Missing values")
        } else {
            val transaction = Transaction(request.getFormAttribute("sender_address")
                    , request.getFormAttribute("recipient_address")
                    , request.getFormAttribute("amount").toInt())
            val result = blockchain.submitTransaction(transaction
                    , Base64.getDecoder().decode(request.getFormAttribute("signature")))
            if (result > 0) {
                val body = JsonObject().put("message", "Transaction will be added to Block $result")
                jsonResponse(rc.response(), 201, body)
            } else {
                val body = JsonObject().put("message", "Invalid Transaction!")
                jsonResponse(rc.response(), 406, body)
            }
        }
    }

    private val listNodes = { rc: RoutingContext ->
        val body = JsonObject().put("nodes", blockchain.nodes.map { it.toString() })
        jsonResponse(rc.response(), 200, body)
    }

    private val registerNode = { rc: RoutingContext ->
        val nodes = rc.request().getFormAttribute("nodes").split(",")

        if (nodes.isEmpty()) {
            textResponse(rc.response(), 400, "Error: Please supply a valid list of nodes")
        } else {
            nodes.forEach { blockchain.registerNode(it.trim()) }
            val body = JsonObject()
                    .put("message", "New nodes have been added")
                    .put("total_nodes", blockchain.nodes.map { it.toString() })
            jsonResponse(rc.response(), 201, body)
        }
    }

    private val mine = { rc: RoutingContext ->
        val lastBlock = blockchain.chain.last()
        val nonce = blockchain.pow()

        rewardMiner(blockchain.nodeId)

        val block = blockchain.createBlock(nonce, lastBlock.sha256().hexString())

        val body = JsonObject()
                .put("message", "New Block Forged")
                .put("block_number", block.blockNumber)
                .put("transactions", block.transactions.map { it.jsonify() })
                .put("nonce", nonce)
                .put("previous_hash", block.previousHash)
        jsonResponse(rc.response(), 200, body)
    }

    private val consensus = { rc: RoutingContext ->
        blockchain.resolveConflic(vertx) { result: Boolean ->
            val body = JsonObject()

            if (result) {
                body.put("message", "Our chain was replaced").put("new_chain", blockchain.chain.map { it.jsonify() })
            } else {
                body.put("message", "Our chain is authoritative").put("chain", blockchain.chain.map { it.jsonify() })
            }

            jsonResponse(rc.response(), 200, body)
        }
    }

    private fun rewardMiner(recipientAddress: String) = blockchain.submitTransaction(Transaction(MINING_SENDER, recipientAddress, MINING_REWARD))
}

data class Transaction(val senderAddress: String, val recipientAddress: String, val amount: Int) {
    companion object {
        fun fromJson(jsonObject: JsonObject) = Transaction(
                jsonObject.getString("sender_address")
                , jsonObject.getString("recipient_address")
                , jsonObject.getInteger("value"))
    }

    fun verify(signature: ByteArray?): Boolean {
        if (signature == null) {
            return false
        }

        val signer = Signature.getInstance("SHA256withRSA")
        signer.initVerify(this.senderAddress.rsaPublicKey())

        val data = jsonify().toString().toByteArray()
        signer.update(data)

        return signer.verify(signature)
    }

    fun jsonify() = JsonObject()
            .put("sender_address", senderAddress)
            .put("recipient_address", recipientAddress)
            .put("value", amount)
}

data class Block(val blockNumber: Int, val ts: Long, val transactions: ArrayList<Transaction>, val nonce: Int
                 , val previousHash: String) {
    companion object {
        fun fromJson(jsonObject: JsonObject): Block {
            val transactions = arrayListOf<Transaction>()
            transactions.addAll(jsonObject.getJsonArray("transactions").map { Transaction.fromJson(it as JsonObject) })

            return Block(jsonObject.getInteger("block_number")
                    , jsonObject.getLong("timestamp")
                    , transactions
                    , jsonObject.getInteger("nonce")
                    , jsonObject.getString("previous_hash"))
        }
    }

    fun jsonify() = JsonObject()
            .put("block_number", blockNumber)
            .put("timestamp", ts)
            .put("transactions", transactions.map { it.jsonify() })
            .put("nonce", nonce)
            .put("previous_hash", previousHash)

    fun sha256() = jsonify().toString().toByteArray().sha256()
}

class Blockchain {
    var currentTransactions: ArrayList<Transaction>
    var chain: ArrayList<Block>
    val nodes: HashSet<String>
    val nodeId: String

    init {
        currentTransactions = arrayListOf()
        chain = arrayListOf()
        nodes = hashSetOf()
        nodeId = UUID.randomUUID().toString().replace("-", "")
        createBlock(0, "00")
    }

    fun createBlock(nonce: Int, previousHash: String): Block {
        val block = Block(this.chain.size + 1
                , Instant.now().epochSecond
                , this.currentTransactions
                , nonce
                , previousHash
        )
        chain.add(block)
        this.currentTransactions = arrayListOf()
        return block
    }

    fun submitTransaction(transaction: Transaction, signature: ByteArray? = null) =
            if (transaction.senderAddress == MINING_SENDER || transaction.verify(signature)) {
                currentTransactions.add(transaction)
                currentTransactions.size + 1
            } else {
                -1
            }

    fun registerNode(nodeUri: String) = nodes.add(nodeUri)

    fun pow(): Int {
        val lastBlock = chain.last()
        val lastHash = lastBlock.sha256()
        var nonce = 0
        while (!validProof(currentTransactions, lastHash, nonce)) {
            nonce++
        }

        return nonce
    }

    fun resolveConflic(vertx: Vertx, handler: (Boolean) -> Unit) {
        val httpClient = vertx.createHttpClient()
        val futures = mutableListOf<Future<HttpClientResponse>>()

        this.nodes.forEach { node ->
            val requestFuture = Future.future<HttpClientResponse>()
            val urlParts = node.split(":")
            val port = if (urlParts.size == 1) 8080 else urlParts[1].toInt()

            httpClient.getNow(port, urlParts[0], "/chain") { response: HttpClientResponse ->
                requestFuture.complete(response)
            }
            futures.add(requestFuture)
        }

        CompositeFuture.join(futures as List<Future<HttpClientResponse>>).setHandler { ar ->
            if (ar.succeeded()) {
                val count = AtomicInteger(0)
                var result = false
                var maxLength = this.chain.size

                futures.forEach { future ->
                    future.result().bodyHandler { buffer ->
                        val body = buffer.toJsonObject()
                        val chain = body.getJsonArray("chain").map { Block.fromJson(it as JsonObject) }
                        val length = body.getInteger("length")

                        if (length > maxLength && this.validChain(chain)) {
                            synchronized(this) {
                                maxLength = length
                                this.chain = chain as ArrayList<Block>
                                result = true
                            }
                        }

                        if (count.incrementAndGet() == futures.size) {
                            handler(result)
                        }
                    }
                }
            } else {
                println("One of requests failsed, cause:")
                println(ar.cause())

                handler(false)
            }
        }
    }

    private fun validProof(transactions: ArrayList<Transaction>, lastHash: ByteArray
                           , nonce: Int, difficulty: Int = MINING_DIFFICULTY): Boolean {
        val guess = transactions.map { it.jsonify() }.joinToString().toByteArray() + lastHash + nonce.toString().toByteArray()
        return guess.sha256().hexString().startsWith((0..difficulty).map { "0" }.joinToString(""))
    }

    private fun validChain(chain: List<Block>): Boolean {
        var lastBlock = chain[0]
        var index = 1

        while (index < chain.size) {
            var currentBlock = chain[index]

            if (currentBlock.previousHash != lastBlock.sha256().hexString()) {
                return false
            }

            val reward = currentBlock.transactions.last()

            currentBlock.transactions.remove(reward)

            if (!validProof(currentBlock.transactions
                    , currentBlock.previousHash.hexStringToByteArray()
                    , currentBlock.nonce)) {
                return false
            }

            currentBlock.transactions.add(reward)

            lastBlock = currentBlock
            index++
        }

        return true
    }

}

fun ByteArray.hexString() = this.map { String.format("%02x", it) }.joinToString("")
fun ByteArray.sha256() = MessageDigest.getInstance("SHA-256").digest(this)

fun PublicKey.key() = Base64.getEncoder().encodeToString(this.encoded)
fun PrivateKey.key() = Base64.getEncoder().encodeToString(this.encoded)

fun String.hexStringToByteArray() = ByteArray(this.length / 2) { this.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

fun String.rsaPrivateKey(): PrivateKey {
    val keyfactory = KeyFactory.getInstance("RSA")
    val keySpec = PKCS8EncodedKeySpec(Base64.getDecoder().decode(this))
    return keyfactory.generatePrivate(keySpec)
}

fun String.rsaPublicKey(): PublicKey {
    val keyfactory = KeyFactory.getInstance("RSA")
    val keySpecPv = X509EncodedKeySpec(Base64.getDecoder().decode(this))
    return keyfactory.generatePublic(keySpecPv)
}

internal fun jsonResponse(response: HttpServerResponse, statusCode: Int, body: JsonObject) {
    response.statusCode = statusCode
    response.putHeader("content-type", "application/json; charset=utf-8")
            .end(body.toString())
}

internal fun textResponse(response: HttpServerResponse, statusCode: Int, body: String) {
    response.statusCode = statusCode
    response.putHeader("content-type", "text/plain; charset=utf-8").end(body)
}