## Go-Pub
This is a basic implementation of the ActivityPub protocol as a way to learn how it works. Currently this supports
- [x] User discovery across the fediverse (Eg- [Mastodon](https://mastodon.social), [Pleroma](https://plemora.site))
- [x] Follow user (Sends `Accept` activity back with HTTP signature)
- [x] Sends a test message to the followee
- [ ] Send message to all the followers