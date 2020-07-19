# CMakeList.txt : CMake project for RSATest, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

if(NOT CMAKE_CL_64)
	set(PYTHON_EXECUTABLE "C:\\Python38-32\\python.exe")
endif()

# Add source to this project's executable.
add_subdirectory(pybind11)

pybind11_add_module(pyrsaref
	"rsaref/des.h"
	"rsaref/desc.c"
	"rsaref/digit.c"
	"rsaref/digit.h"
	"rsaref/global.h"
	"rsaref/md2.h"
	"rsaref/md2c.c"
	"rsaref/md5.h"
	"rsaref/md5c.c"
	"rsaref/nn.c"
	"rsaref/nn.h"
	"rsaref/prime.c"
	"rsaref/prime.h"
	"rsaref/r_dh.c"
	"rsaref/r_encode.c"
	"rsaref/r_enhanc.c"
	"rsaref/r_keygen.c"
	"rsaref/r_random.c"
	"rsaref/r_random.h"
	"rsaref/r_stdlib.c"
	"rsaref/rsa.c"
	"rsaref/rsa.h"
	"rsaref/rsaref.h"

	"CryptRSA.cpp"
	"CryptRSA.h"

	"pyrsaref.cpp"
)

add_executable (RSATest
	"rsaref/des.h"
	"rsaref/desc.c"
	"rsaref/digit.c"
	"rsaref/digit.h"
	"rsaref/global.h"
	"rsaref/md2.h"
	"rsaref/md2c.c"
	"rsaref/md5.h"
	"rsaref/md5c.c"
	"rsaref/nn.c"
	"rsaref/nn.h"
	"rsaref/prime.c"
	"rsaref/prime.h"
	"rsaref/r_dh.c"
	"rsaref/r_encode.c"
	"rsaref/r_enhanc.c"
	"rsaref/r_keygen.c"
	"rsaref/r_random.c"
	"rsaref/r_random.h"
	"rsaref/r_stdlib.c"
	"rsaref/rsa.c"
	"rsaref/rsa.h"
	"rsaref/rsaref.h"

	"CryptRSA.cpp"
	"CryptRSA.h"

	"RSATest.cpp"
	
	)

# TODO: Add tests and install targets if needed.
