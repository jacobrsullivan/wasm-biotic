This scenario validates the `v2.3` coordination-domain topology map.

It proves that:
- campaign, epoch, session, queue, scheduler, and replay/recovery scopes are explicit,
- topology is presented as a runtime contract surface rather than local implementation trivia,
- and later `v2` lines can inherit one shared topology map.
