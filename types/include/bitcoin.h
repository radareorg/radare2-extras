/*

https://bitcoin.org/en/developer-reference#block-headers

02000000 ........................... Block version: 2

b6ff0b1b1680a2862a30ca44d346d9e8
910d334beb48ca0c0000000000000000 ... Hash of previous block's header
9d10aa52ee949386ca9385695f04ede2
70dda20810decd12bc9b048aaab31471 ... Merkle root

24d95a54 ........................... Unix time: 1415239972
30c31b18 ........................... Target: 0x1bc330 * 256**(0x18-3)
fe9f0864 ........................... Nonce

--------- versions

Version 1 was introduced in the genesis block (January 2009).

Version 2 was introduced in Bitcoin Core 0.7.0 (September 2012) as a soft fork. As described in BIP34, valid version 2 blocks require a block height parameter in the coinbase. Also described in BIP34 are rules for rejecting certain blocks; based on those rules, Bitcoin Core 0.7.0 and later versions began to reject version 2 blocks without the block height in coinbase at block height 224,412 (March 2013) and began to reject new version 1 blocks three weeks later at block height 227,930.

Version 3 blocks were introduced in Bitcoin Core 0.10.0 (February 2015) as a soft fork. When the fork reach full enforcement (July 2015), it required strict DER encoding of all ECDSA signatures in new blocks as described in BIP66. Transactions that do not use strict DER encoding had previously been non-standard since Bitcoin Core 0.8.0 (February 2012).

Version 4 blocks specified in BIP65 and introduced in Bitcoin Core 0.11.2 (November 2015) as a soft fork became active in December 2015. These blocks now support the new OP_CHECKLOCKTIMEVERIFY opcode described in that BIP.

*/
typedef struct bitcoin_block {
	int32_t version;
	char previous[32]; // sha256(sha256()) of the previous block
	char merkleroot[32]; // sha256(sha256())
	uint32_t time;
	uint32_t nbits;
	uint32_t nonce;
} bitcoin_block_t;
