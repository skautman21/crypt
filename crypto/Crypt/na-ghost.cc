#include "na-gost.h"
#include <iomanip>
#include <algorithm>
namespace na
{
namespace na_gost
{
const uint32_t T_SWAP[16] = {3, 5, 4, 8, 9, 1, 11, 13, 12, 0, 15, 2, 7, 6, 10, 14};
//

static const uint8_t TABLE_PI[8][16] {
			{12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1},
			{6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15},
			{11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0},
			{12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11},
			{7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12},
			{5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0},
			{8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7},
			{1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2}
};
using crypto_function = std::function<void(
		const uint8_t *, const uint8_t *, uint8_t *)>;

void gost_34_12_2012_64_t_transform(
		const uint8_t	*src_block,
		uint8_t			*dst_block)
{
	for (unsigned i = 0; i < 4; i++)
	{
		uint8_t lsb = src_block[i] & 0x0f;
		uint8_t msb = (src_block[i] >> 4) & 0x0f;
		lsb = TABLE_PI[i*2 + 0][lsb];
		msb = TABLE_PI[i*2 + 1][msb];
		dst_block[i] = (msb << 4) | lsb;
	}
}

static uint32_t gost_34_12_2012_64_t_cipher(
		 uint32_t	a,
		 uint32_t	k)
{
	uint32_t b = (a + k);
	uint8_t *bp = reinterpret_cast<uint8_t*>(&b);
	gost_34_12_2012_64_t_transform(bp, bp);
	b = (b << 11) | (b >> (32-11));
	return b;
}

static void gost_34_12_2012_64_key_expand(
		const uint8_t	*key,
		uint32_t		*expanded_key)
{
	const uint32_t *k = reinterpret_cast<const uint32_t*>(key);
	for (unsigned i = 0; i < 8; i++)
	{
		expanded_key[7-i] = k[i];
		expanded_key[7-i+8] = k[i];
		expanded_key[7-i+16] = k[i];
		expanded_key[7-i+24] = k[7-i];
	}
}

void feistel(
		const uint8_t 	*src_block,
		uint32_t 		block_size,
		const uint8_t 	*key,
		uint32_t 		key_length,
		uint32_t 		rounds_count,
		bool 			reverse_key,
		crypto_function	cf,
		uint8_t			*dst_block)
{
	uint32_t round_key_length = key_length / rounds_count;
	uint32_t subblock_size = block_size / 2;

	uint8_t L_before[subblock_size], R_before[subblock_size];
	uint8_t L_after[subblock_size], R_after[subblock_size];
	memcpy(L_before, src_block, subblock_size);
	memcpy(R_before, src_block + subblock_size, subblock_size);

	for (uint32_t round = 0; round < rounds_count; round++)
	{
		memcpy(L_after, R_before, subblock_size);
		const uint8_t *round_key = reverse_key?
				(key + round_key_length * (rounds_count - round -1)) :
				(key + round_key_length * round);
		cf(L_before, round_key, R_after);
		uint32_t k = 0;
		for ( uint8_t *a = R_after, *b = R_before;
				k < subblock_size; a++, b++, k++)
			*a ^= *b;
		memcpy(L_before, R_after, subblock_size);
		memcpy(R_before, R_after, subblock_size);
	}
	memcpy(dst_block, R_after, subblock_size);
	memcpy(dst_block + subblock_size, L_after, subblock_size);
}

void gost_34_12_2018_64(
		const uint8_t	*src_block,
		const uint8_t	*key,
		bool			reverse_key,
		uint8_t			*dst_block)
{
	uint32_t expanded_key[32];
	uint8_t *expanded_key_ptr = reinterpret_cast<uint8_t*>(&expanded_key);
	gost_34_12_2012_64_key_expand(key, expanded_key);
//	uint32_t *src = reinterpret_cast<uint32_t*>(src_block);
//	uint32_t *dst = reinterpret_cast<uint32_t*>(dst_block);
	feistel(src_block, 8,
			expanded_key_ptr, 32*4,
			32, reverse_key,
			[&](const uint8_t * blk, const uint8_t *key, uint8_t *res)
			{
				auto blk_ptr = reinterpret_cast<const uint32_t *>(blk);
				auto key_ptr = reinterpret_cast<const uint32_t *>(key);
				auto res_ptr = reinterpret_cast<uint32_t *>(res);
				*res = gost_34_12_2012_64_t_cipher(*blk_ptr, *key_ptr);
			},
			dst_block);

}
}
}
