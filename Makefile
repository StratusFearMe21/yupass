install:
	cargo build --release
	sudo cp target/release/yupass /usr/bin
