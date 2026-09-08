.PHONY: prepare verify reproduce test protocol nile
.NOTPARALLEL:

# Explicitly regenerates fixtures. Use reproduce to compare without overwriting them.
prepare:
	./scripts/prepare_all.sh

verify:
	./scripts/verify_fixtures.sh

reproduce:
	./scripts/reproduce.sh

test:
	$(MAKE) verify
	$(MAKE) reproduce

protocol:
	./scripts/verify_protocol.sh

nile:
	node tools/nile.mjs
