PYTHON   := .venv/bin/python
PIP      := .venv/bin/pip
SRC      := examples/nuitka/main.py
OUT_DIR  := dist
BIN      := $(OUT_DIR)/main.bin
VERSION  ?= 1.2.4
PRIVATE_KEY ?= demo-keys/private.pem
PUBLIC_KEY  ?= demo-keys/public.pem

.PHONY: all venv deps build stamp run version verify keygen sign test clean

all: build stamp

venv:
	python3 -m venv .venv

deps: venv
	$(PIP) install -U pip
	$(PIP) install nuitka zstandard ordered-set
	$(PIP) install -e ".[signing]"

build:
	$(PYTHON) -m nuitka \
		--onefile \
		--assume-yes-for-downloads \
		--output-dir=$(OUT_DIR) \
		$(SRC)

stamp: $(BIN)
	$(PYTHON) -m tailmeta stamp $(BIN) --version "$(VERSION)"

sign: $(BIN)
	$(PYTHON) -m tailmeta stamp $(BIN) --version "$(VERSION)" --private-key "$(PRIVATE_KEY)"

keygen:
	mkdir -p "$(dir $(PRIVATE_KEY))" "$(dir $(PUBLIC_KEY))"
	$(PYTHON) -m tailmeta keygen --private-key "$(PRIVATE_KEY)" --public-key "$(PUBLIC_KEY)"

verify: $(BIN)
	$(PYTHON) -m tailmeta verify $(BIN) --public-key "$(PUBLIC_KEY)"

run: $(BIN)
	./$(BIN)

version: $(BIN)
	@$(PYTHON) -m tailmeta read $(BIN) --version-only

test: build
	$(PYTHON) -m unittest discover -s tests -v
	$(PYTHON) examples/nuitka/test_onefile.py $(BIN)

clean:
	rm -rf $(OUT_DIR) main.build main.dist main.onefile-build
