// RUN: %check_clang_tidy %s misc-convert-methods-to-global-functions %t

// FIXME: Verify the applied fix.
//   * Make the CHECK patterns specific enough and try to make verified lines
//     unique to avoid incorrect matches.
//   * Use {{}} for regular expressions.
// CHECK-FIXES: {{^}}void awesome_f();{{$}}

#include <vector>

struct NoStd {
	int a;

	void begin() {

	}
};

struct Foo {
 	std::vector<int> numbers;
	auto getNumbers(){
		return numbers;
	}
};

#define concat(a,b,c) a.b##c()

int main(void) {

	NoStd asdf;
	asdf.begin();

	std::vector<int> v;
	auto a = v.begin();
	auto b = v.end();
	bool c = v.empty();
	std::size_t d = v.size();

	for (auto i : v) {
		
	} 

	std::vector<int> size;
	for (auto i : size) {
		
	} 

	concat(size, be, gin);

	struct Foo f;
	auto g  = f.numbers.size();
	auto g2 = f.getNumbers().size();

    auto x = &v;
    x->end();
	
	return 0;
}

