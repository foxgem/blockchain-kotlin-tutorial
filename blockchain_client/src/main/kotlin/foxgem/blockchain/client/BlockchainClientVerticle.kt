package foxgem.blockchain.client

import io.vertx.core.AbstractVerticle
import io.vertx.core.http.HttpServerResponse
import io.vertx.core.json.JsonObject
import io.vertx.ext.web.Router
import io.vertx.ext.web.RoutingContext
import io.vertx.ext.web.handler.BodyHandler
import io.vertx.ext.web.handler.StaticHandler
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.util.*

class BlockchainClientVerticle : AbstractVerticle() {

    override fun start() {
        val router = Router.router(vertx)

        router.route().handler(StaticHandler.create())
        router.get("/wallet/new").handler(walletGenerator)
        router.get("/make/transaction").handler({ rc: RoutingContext -> rc.reroute("/make_transaction.html") })
        router.get("/view/transactions").handler({ rc: RoutingContext -> rc.reroute("/view_transactions.html") })
        router.post("/generate/transaction").handler(BodyHandler.create()).handler(transactionGenerator)

        vertx.createHttpServer().requestHandler({ router.accept(it) }).listen(8080)
    }

}

data class Transaction(val senderAddress: String, val senderPrivateKey: String, val recipientAddress: String, val amount: Int) {

    fun sign(): String {
        val signature = Signature.getInstance("SHA256withRSA")
        signature.initSign(this.senderPrivateKey.rsaPrivateKey())

        val data = this.toString().toByteArray()
        signature.update(data)

        return Base64.getEncoder().encodeToString(data)
    }

    fun jsonify() = JsonObject()
            .put("sender_address", senderAddress)
            .put("recipient_address", recipientAddress)
            .put("value", amount)

}

val walletGenerator = { rc: RoutingContext ->
    val kpg = KeyPairGenerator.getInstance("RSA")
    kpg.initialize(1024)

    val keyPair = kpg.genKeyPair()

    jsonResponse(rc.response()
            , 200
            , JsonObject(hashMapOf("private_key" to keyPair.private.key(), "public_key" to keyPair.public.key()).toMap()))
}

val transactionGenerator = { rc: RoutingContext ->
    val request = rc.request()
    val transaction = Transaction(senderAddress = request.getFormAttribute("sender_address")
            , senderPrivateKey = request.getFormAttribute("sender_private_key")
            , recipientAddress = request.getFormAttribute("recipient_address")
            , amount = request.getFormAttribute("amount").toInt())

    val body = JsonObject()
    body.put("transaction", transaction.jsonify())
    body.put("signature", transaction.sign())

    jsonResponse(rc.response(), 200, body)
}

fun PublicKey.key() = Base64.getEncoder().encodeToString(this.encoded)
fun PrivateKey.key() = Base64.getEncoder().encodeToString(this.encoded)

fun String.rsaPrivateKey(): PrivateKey {
    val keyfactory = KeyFactory.getInstance("RSA")
    val keySpec = PKCS8EncodedKeySpec(Base64.getDecoder().decode(this))
    return keyfactory.generatePrivate(keySpec)
}

fun String.rsaPublicKey(): PublicKey {
    val keyfactory = KeyFactory.getInstance("RSA")
    val keySpecPv = PKCS8EncodedKeySpec(Base64.getDecoder().decode(this))
    return keyfactory.generatePublic(keySpecPv)
}

internal fun jsonResponse(response: HttpServerResponse, statusCode: Int, body: JsonObject) {
    response.statusCode = statusCode
    response.putHeader("content-type", "application/json; charset=utf-8")
            .end(body.toString())
}