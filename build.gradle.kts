plugins {
    application
    id("ecbuild.java-conventions")
    id("ecbuild.copy-conventions")
    alias(libs.plugins.git)
}

application {
    mainClass = "org.itxtech.nemisys.Nemisys"
}

extra.set("copyTo", listOf("proxy", "login-proxy"))

gitProperties {
    dateFormat = "yyyy.MM.dd '@' HH:mm:ss z"
    failOnNoGitDirectory = false
    dotGitDirectory = rootProject.file(".git")
}

dependencies {
    val authLibPkg = findProject(":AuthLibPackage")
    if (authLibPkg == null) {
        api(files(File(rootProject.projectDir, "lib/AuthLibPackage.jar")))
    } else {
        api(project(":AuthLibPackage"))
    }
    api(project(":Network:raknet"))
    api(libs.apache.commons.compress)
    api(libs.apache.commons.lang3)
    api(libs.commons.io)
    api(libs.fastutil)
    api(libs.gson)
    api(libs.guava)
    api(libs.jackson)
    api(libs.jackson.datatype.guava)
    api(libs.jackson.datatype.jdk8)
    api(libs.jline.reader)
    api(libs.jline.terminal)
    api(libs.jopt)
    api(libs.jwt)
    api(libs.lmax.disruptor)
    api(libs.lmbda)
    api(libs.log4j.core)
    annotationProcessor(libs.log4j.core)
    api(libs.log4j.slf4j2)
    api(libs.maven.provider)
    api(libs.maven.connector)
    api(libs.maven.http)
    api(libs.minecrell.console)
    api(libs.netty.all)
    api(libs.nukkitx.natives)
    api(libs.org.cloudburstmc.upnp)
    api(libs.slf4j.api)
    api(libs.snakeyaml)
    api(libs.snakeyaml.engine)
    api(libs.snappy)
    api(libs.zstd)
}

group = "org.itxtech.nemisys"
description = "Nemisys"
