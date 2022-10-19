# Running Instruction

## Generate RSA keys first

-   `openssl genrsa 2048 > private.pem`
-   `openssl rsa -in private.pem -pubout -out public.pem`
-   `openssl genrsa 4096 > private2.pem`
-   `openssl rsa -in private2.pem -pubout -out public2.pem`

## Run Sender Receiver

-   `cargo run --bin sender <message to encrypt>`
-   `cargo run --bin receiver`

-   Can change AES_KEY in `src/lib.rs`
-   Can change HMAC_KEY in `src/lib.rs`
