# kevstig — build + gate. The scheduled job owns fetch/deploy/verify.

.PHONY: build gate

build:
	python3 kevstig.py --kev /tmp/kev.json \
		--baselines ../stig-baselines/baselines \
		--out /tmp/kevstig-deploy

gate: build
	@echo "gate verdict: see KEVSTIG-OK line above"