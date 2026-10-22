// Root project. Plugin versions are pinned in app/build.gradle.kts.
tasks.register<Delete>("clean") {
    delete(rootProject.layout.buildDirectory)
}
