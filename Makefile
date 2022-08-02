build: oauth2_clientd/*.py scripts/oauth2-clientd
	python3 setup.py build

test: build
	mypy oauth2_clientd scripts/oauth2-clientd
	pylint oauth2_clientd
	pylint --from-stdin script < scripts/oauth2-clientd
