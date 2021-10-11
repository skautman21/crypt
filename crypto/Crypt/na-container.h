

#ifndef NA_CONTAINER_H_
#define NA_CONTAINER_H_
namespace nc
{

namespace container
{
// MAGIC number = "DRUG"

constexpr uint32_t MAGIC =
		0x00000001 * 'D' +
		0x00000100 * 'R' +
		0x00010000 * 'U' +
		0x01000000 * 'G' ;

enum payload_type
{
	RAW = 0,
	KEY_DATA,
	ENCRYPTED_DATA,
	DH_PARAMS,
};
enum crypt_type
{
	RAW_CRYPT = 0,
	ECB_CRYPT,
	CBC_CRYPT,
	CTR_CRYPT
};

constexpr uint32_t HEADER_SIZE_V1 = 12;
constexpr uint32_t FILE_METADATA_SIZE_V1_BASE = 24;

#pragma pack(push, 1)

struct header
{
	uint32_t magic;
	uint32_t header_size;

	union {
		struct {
			uint8_t payload;
			uint8_t crypt;
			uint8_t padding[2];
		} v1;
	};
};

struct metadata
{
	uint32_t length;

	union {
		struct {
			uint64_t orig_length;
			uint64_t block_count;
			uint32_t block_size;

		} file;
		struct {
			uint64_t orig_length;
			uint64_t block_count;
			uint32_t block_size;
		} key;
		struct {

		} dh_params;
	};
};

#pragma pack(pop)

}

}

#endif /* NA_CONTAINER_H_ */
