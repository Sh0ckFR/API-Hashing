#include "stdafx.hpp"

int main() {
	const char* entity = "MessageBoxW";
    unsigned long hash = api::djn1l((unsigned char*)entity);
    printf("The hash of %s is 0x%08lx\n", entity, hash);

    api::get<MESSAGEBOXW>(H_USER32, H_MESSAGEBOXW)(0, L"It works", L"Hello", 0);
    return 0;
}
