SHELL := /bin/bash
DB_URL ?= postgres://sanca:sanca@localhost:5433/sanca_dev
export DATABASE_URL := $(DB_URL)

.PHONY: help db db-down dev run build test fmt clippy migrate prepare docker docker-run

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

docker:          ## build image
	docker build -t sanca:local .

docker-run:      ## jalankan image via compose (profil app)
	docker compose --profile app up -d --build
