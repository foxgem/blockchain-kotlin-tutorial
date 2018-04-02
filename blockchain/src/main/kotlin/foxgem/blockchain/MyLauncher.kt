package foxgem.blockchain.client

import io.vertx.core.Launcher


class MyLauncher : Launcher()

fun main(args: Array<String>) {
    MyLauncher().dispatch(args)
}