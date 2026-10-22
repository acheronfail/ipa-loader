# Sharing adapter

Maps authorized app-group and keychain-group IDs from `IPALoaderSharing` metadata
for Foundation and Security APIs. Requires thin arm64 code with spare Mach-O
header space. Build with the platform's `build-sharing-*` recipe.

[fishhook](https://github.com/facebook/fishhook) is pinned to
`aadc161ac3b80db07a9908851839a17ba63a9eb1`; see [LICENSE.fishhook](LICENSE.fishhook).
