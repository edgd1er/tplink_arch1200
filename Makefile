.PHONY: lint flake build help all

MAKEPATH := $(abspath $(lastword $(MAKEFILE_LIST)))
PWD := $(dir $(MAKEPATH))

#help:
#		@$(MAKE) -pRrq -f $(lastword $(MAKEFILE_LIST)) : 2>/dev/null | awk -v RS= -F: '/^# Fichiers/,/^# Base/ {if ($$1 !~ "^[#.]") {print $$1}}' | sort | egrep -v -e '^[^[:alnum:]]' -e '^$@$$'

# https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
help: ## generate help list
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

all: lint flake build

lint: ## lint python files
		pylint .

flake: ## lint python files
		flake8 .

test: ## run coverage with UT
		@echo "run unittest + cover"
		coverage run -a tests/test_duckdns.py -u -d
		coverage run -a tests/test_noip.py -u -d
		coverage run -a tests/test_archer1200.py -u -d
		#coverage run tests/test_updateDuckDns.py
		pytest
		coverage html
		coverage report

func: ## run archer functionnal tests
		./tests/test_archer1200.py -f

report: ## get cover report
		coverage json
		coverage html
		coverage report

up:
		docker compose -f docker-compose.yml up

genreq:
		pip3 freeze > requirements.txt