#include <iomanip>

#ifndef NA_GOST_H_
#define NA_GOST_H_

namespace na
{
namespace na_gost
{
void gost_34_12_2018_64(
		const uint8_t	*src_block,
		const uint8_t	*key,
		bool			reverse_key,
		uint8_t			*dst_block);
}
}

#endif /* CTB_CRYPT_GOST_H_ */