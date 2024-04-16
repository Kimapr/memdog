#include <stdlib.h>
#include <memory.h>
int main() {
	for(;;) {
		memset(malloc(0x10000),1,0x10000);
	}
}
