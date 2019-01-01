# Mediatek AES Crypto Engine

This AES Engine is available in the Mediatek MT76x8 SoC.

It enables hardware crypto for AES-ECB and AES-CBC with 128/192/256 keysize.

This should be added to your device DTS or better yet to the mt76x8.dtsi:

	crypto: crypto@10004000 {
		compatible = "mediatek,mtk-aes";
		reg = <0x10004000 0x1000>;

		interrupt-parent = <&intc>;
		interrupts = <13>;

		resets = <&rstctrl 29>;
		reset-names = "cryp";
		clocks = <&clkctrl 29>;
		clock-names = "cryp";
	};

Benchmark: By default crypto-blocks <100 bytes are software only

You have chosen to measure elapsed time instead of user CPU time.

Doing aes-256-cbc for 3s on 16 size blocks: 358615 aes-256-cbc's in 3.00s

Doing aes-256-cbc for 3s on 64 size blocks: 184798 aes-256-cbc's in 3.00s

Doing aes-256-cbc for 3s on 256 size blocks: 152296 aes-256-cbc's in 3.00s

Doing aes-256-cbc for 3s on 1024 size blocks: 120724 aes-256-cbc's in 3.00s

Doing aes-256-cbc for 3s on 8192 size blocks: 36151 aes-256-cbc's in 3.00s

The 'numbers' are in 1000s of bytes per second processed.

type		16 bytes     64 bytes    256 bytes   1024 bytes   8192 bytes

aes-256-cbc	1912.61k     3942.36k    12995.93k    41207.13k    98716.33k

