# Channels

This branch holds the pointer of each release channel of the catalogue, `edge.json` and, once
releases are promoted, `stable.json`: the release the channel names and the SHA-256 of its
manifest, as [`schemas/channel.schema.json`](https://github.com/OpenAEV-Platform/scenarios/blob/main/schemas/channel.schema.json)
describes. Only the release workflow writes here. How to read a pointer and the release it names
is in [`docs/consumers.md`](https://github.com/OpenAEV-Platform/scenarios/blob/main/docs/consumers.md).
