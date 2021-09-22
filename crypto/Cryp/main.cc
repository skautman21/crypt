#include <iostream>
#include <fstream>
#include <cstring>
#include <stdint.h>
#include <algorithm>

#include <WOW.h>

const char * TEST_FILE_NAME = "test.txt";
const char * TEST_CONTAINER_NAME = "tect_c.artk";
const uint32_t TEST_BLOCK_SIZE = 32;

void test_create_container()
{
	std::ifstream src_file;
	std::ofstream dst_file;

	src_file.open(TEST_FILE_NAME, std::ios::binary | std::ios::ate);
	size_t filesize = src_file.tellg();
	src_file.seekg(0);

	dst_file.open(TEST_CONTAINER_NAME, std::ios::binary);

	using namespace ec::container;

	header hdr {};
	hdr.magic = MAGIC;
	//hdr.version = 1;
	hdr.header_size = HEADER_SIZE_V1;
	hdr.v1.payload = RAW;
	dst_file.write(reinterpret_cast<char*>(&hdr), HEADER_SIZE_V1);

	metadata md {};
	uint32_t name_length = strlen(TEST_FILE_NAME);
	md.length = FILE_METADATA_SIZE_V1_BASE + name_length + 1;
	md.file.orig_length = filesize;
	md.file.block_size = TEST_BLOCK_SIZE;
	md.file.block_count = filesize / (TEST_BLOCK_SIZE / 8);
	if (filesize % (TEST_BLOCK_SIZE / 8) > 0)
		md.file.block_count++;
	dst_file.write(reinterpret_cast<char*>(&md), FILE_METADATA_SIZE_V1_BASE);
	dst_file.write(TEST_FILE_NAME, name_length + 1);

	for (uint64_t block = 0; block <md.file.block_count; block++)
	{
		uint8_t buffer[TEST_BLOCK_SIZE / 8] {};
		src_file.readsome(reinterpret_cast<char*>(&buffer[0]),
				TEST_BLOCK_SIZE / 8);
		dst_file.write(reinterpret_cast<char*>(&buffer[0]),
				TEST_BLOCK_SIZE / 8);
	}

	src_file.close();
	dst_file.close();
}

void test_extract_container()
{
	std::ifstream src_file;
	std::ofstream dst_file;

	using namespace ec::container;

	src_file.open(TEST_CONTAINER_NAME, std::ios::binary);
	header hdr {};
	src_file.readsome(reinterpret_cast<char*>(&hdr),
			sizeof(header));
	if (hdr.magic != MAGIC) {
		std::cerr <<
				"Контейнер сломался"
				<< std::endl;
		return;
	}
	if (hdr.v1.payload != RAW) {
		std::cerr <<
				"Отсутствует RAW в контейнере"
				<< std::endl;
		return;
	}
	src_file.seekg(hdr.header_size);

	uint64_t pos_after_header = src_file.tellg();

	metadata md {};
	src_file.readsome(reinterpret_cast<char*>(&md),
			FILE_METADATA_SIZE_V1_BASE);
	std::string orig_file_name = "CK_";
	char c;
	while ((c = src_file.get())){
		orig_file_name += c;
	}

	dst_file.open(orig_file_name.c_str(), std::ios::binary);
	src_file.seekg(pos_after_header + md.length);

	while(md.file.orig_length > 0)
	{
		uint8_t buffer[TEST_BLOCK_SIZE / 8] {};
		src_file.read(reinterpret_cast<char*>(&buffer[0]),
				TEST_BLOCK_SIZE / 8);
		uint64_t bytes_to_write = std::min<unsigned long>(4UL, md.file.orig_length);
		dst_file.write(
				reinterpret_cast<char*>(&buffer[0]),
				bytes_to_write);
		md.file.orig_length -= bytes_to_write;

	}

	dst_file.close();
	src_file.close();


}

int main (int argc, char ** argv)
{
	test_create_container();
	test_extract_container();

	return 0;
}



