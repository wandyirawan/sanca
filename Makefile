SHELL := /bin/bash
DB_URL ?= postgres://sanca:sanca@localhost:5433/sanca_dev
export DATABASE_URL := $(DB_URL)

.PHONY: help db db-down dev run build test fmt clippy migrate prepare docker docker-run seed-admin

help:            ## daftar target
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

db:              ## postgres 18 saja (dev)
	docker compose up -d db
	@until docker compose exec -T db pg_isready -U sanca -d sanca_dev >/dev/null 2>&1; do sleep 0.5; done

db-down:         ## hentikan database dev
	docker compose down

dev:             ## auto-reload: src/, migrations/, assets/
	cargo watch -w src -w migrations -w assets -x "run --bin sanca"

run:             ## jalankan server
	cargo run --bin sanca

build:           ## build release
	cargo build --release

test:            ## jalankan test
	cargo test

fmt:             ## format kode
	cargo fmt --all

clippy:          ## lint ketat
	cargo clippy --all-targets -- -D warnings

migrate:         ## terapkan migrasi database
	sqlx migrate run

prepare:         ## refresh cache .sqlx (wajib setelah ubah query)
	cargo sqlx prepare -- --all-targets

# Seed admin pertama. Password TIDAK boleh ditulis di Makefile atau argumen:
# dibaca dari stdin, jadi tidak muncul di `ps` maupun riwayat shell.
# Contoh: ADMIN_EMAIL=admin@contoh.id make seed-admin < password.txt
seed-admin:      ## buat user superadmin (ADMIN_EMAIL, password dari stdin)
	@test -n "$(ADMIN_EMAIL)" || (echo "ADMIN_EMAIL wajib diisi" >&2; exit 1)
	cargo run --bin sanca -- user create \
		--email "$(ADMIN_EMAIL)" \
		--display-name "$(ADMIN_NAME)" \
		--superadmin \
		--password-stdin

docker:          ## build image
	docker build -t sanca:local .

docker-run:      ## jalankan image via compose (profil app)
	docker compose --profile app up -d --build
