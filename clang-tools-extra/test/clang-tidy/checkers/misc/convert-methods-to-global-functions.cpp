// RUN: %check_clang_tidy %s misc-convert-methods-to-global-functions %t -std=c++17

// FIXME: Verify the applied fix.
//   * Make the CHECK patterns specific enough and try to make verified lines
//     unique to avoid incorrect matches.
//   * Use {{}} for regular expressions.
// C H E C K-FIXES: {{^}}void awesome_f();{{$}}

namespace std {
  typedef unsigned long long size_t;
  template<class T>
  struct vector{
    T* begin(){return nullptr;}
    T* end(){return nullptr;}
    bool empty() const{return true;}
    size_t size() const{return 0;}
    const T* cbegin()const{return nullptr;}
    const T* crbegin()const{return nullptr;}
    T* rbegin(){return nullptr;}
    T* rend(){return nullptr;}
    const T* cend()const{return nullptr;}
    const T* crend()const{return nullptr;}
    void swap(vector<T>&o){};
  };
  template <class T>
  void swap(T&,T&){}
}

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
struct D:std::vector<int>{
  std::size_t foo(){
    return std::vector<int>::size();
  }
};

#define concat(a,b,c) a.b##c()

int main(void) {

	NoStd asdf;
	asdf.begin();
  // CHECK-MESSAGES: [[@LINE-1]]:13: warning: is not using the global version [misc-convert-methods-to-global-functions]
  // CHECK-FIXES: std::begin(asdf)

	std::vector<int> v,v2;
//  v.swap(v2);
  // C HECK-MESSAGES: [[@LINE-1]]:12: warning: is not using the global version [misc-convert-methods-to-global-functions]
  // C HECK-FIXES: std::swap(v, v2)
	auto a = v.begin();
  // CHECK-MESSAGES: [[@LINE-1]]:19: warning: is not using the global version [misc-convert-methods-to-global-functions]
  // CHECK-FIXES: std::begin(v)
	auto b = v.end();
  // CHECK-MESSAGES: [[@LINE-1]]:17: warning: is not using the global version [misc-convert-methods-to-global-functions]
  // CHECK-FIXES: std::end(v)
	bool c = v.empty();
  // CHECK-MESSAGES: [[@LINE-1]]:19: warning: is not using the global version [misc-convert-methods-to-global-functions]
  // CHECK-FIXES: std::empty(v)
	std::size_t d = v.size();
  // CHECK-MESSAGES: [[@LINE-1]]:25: warning: is not using the global version [misc-convert-methods-to-global-functions]
  // CHECK-FIXES: std::size(v)

	for (auto i : v) {
		
	} 

	std::vector<int> size;
	for (auto i : size) {
		
	} 

	concat(size, be, gin);

	struct Foo f;
	auto g  = f.numbers.size();
  // CHECK-MESSAGES: [[@LINE-1]]:27: warning: is not using the global version [misc-convert-methods-to-global-functions]
  // CHECK-FIXES: std::size(f.numbers)
	auto g2 = f.getNumbers().size();
  // CHECK-MESSAGES: [[@LINE-1]]:32: warning: is not using the global version [misc-convert-methods-to-global-functions]
  // CHECK-FIXES: std::size(f.getNumbers())

  auto x = &v;
  x->end();
  // CHECK-MESSAGES: [[@LINE-1]]:10: warning: is not using the global version [misc-convert-methods-to-global-functions]
  // CHECK-FIXES: std::end(*x)
  std::vector<std::vector<int>> vec;

  for (int x: *vec.begin()){
    // CHECK-MESSAGES: [[@LINE-1]]:26: warning: is not using the global version [misc-convert-methods-to-global-functions]
    // CHECK-FIXES: std::begin(vec)
    vec.cbegin();
    // CHECK-MESSAGES: [[@LINE-1]]:16: warning: is not using the global version [misc-convert-methods-to-global-functions]
    // CHECK-FIXES: std::cbegin(vec)
  }
  vec.crend();
  // CHECK-MESSAGES: [[@LINE-1]]:13: warning: is not using the global version [misc-convert-methods-to-global-functions]
  // CHECK-FIXES: std::crend(vec)
  vec.rend();
  // CHECK-MESSAGES: [[@LINE-1]]:12: warning: is not using the global version [misc-convert-methods-to-global-functions]
  // CHECK-FIXES: std::rend(vec)
  vec.rbegin();
  // CHECK-MESSAGES: [[@LINE-1]]:14: warning: is not using the global version [misc-convert-methods-to-global-functions]
  // CHECK-FIXES: std::rbegin(vec)
  vec.crbegin();
  // CHECK-MESSAGES: [[@LINE-1]]:15: warning: is not using the global version [misc-convert-methods-to-global-functions]
  // CHECK-FIXES: std::crbegin(vec)
	
  vec.cend();
  // CHECK-MESSAGES: [[@LINE-1]]:12: warning: is not using the global version [misc-convert-methods-to-global-functions]
  // CHECK-FIXES: std::cend(vec)
	return 0;
}

