#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "CryptRSA.h"


namespace py = pybind11;

PYBIND11_MODULE(pyrsaref, m) {
    m.doc() = R"pbdoc(
        pyrsaref
        -----------------------
        .. currentmodule:: pyrsaref
        .. autosummary::
           :toctree: _generate
           make_keys
           set_key
           set_randstate
           encrypt
           decrypt
           get_data
    )pbdoc";

    py::class_<CryptRSA>(m, "CryptRSA")
        
        .def(py::init<>())
        .def("make_keys", &CryptRSA::MakeKeys)
        .def("set_key", [](CryptRSA& rsa, py::bytes b, int mode) {
            char* buffer;
            ssize_t length;
            PYBIND11_BYTES_AS_STRING_AND_SIZE(b.ptr(), &buffer, &length);

            rsa.SetKey((unsigned char*)buffer, length, mode);
        })

        .def("get_key", [](CryptRSA& rsa, int mode) {
            int out_size = 0;
            auto key = rsa.GetKey(&out_size, mode);
            return py::bytes((char*)key, out_size);
        })

        .def("set_randstate", [](CryptRSA& rsa, py::bytes b) {
            char* buffer;
            ssize_t length;
            PYBIND11_BYTES_AS_STRING_AND_SIZE(b.ptr(), &buffer, &length);

            memcpy(&rsa.random_struct, buffer, length);
        })

        .def("encrypt", [](CryptRSA& rsa, py::bytes b, int mode) {
            char* buffer;
            ssize_t length;
            PYBIND11_BYTES_AS_STRING_AND_SIZE(b.ptr(), &buffer, &length);

            rsa.Encrypt((unsigned char*)buffer, length, mode);
        })

        .def("decrypt", [](CryptRSA& rsa, py::bytes b, int mode) {
            char* buffer;
            ssize_t length;
            PYBIND11_BYTES_AS_STRING_AND_SIZE(b.ptr(), &buffer, &length);

            rsa.Decrypt((unsigned char*)buffer, length, mode);
        })

        .def("get_data", [](CryptRSA& rsa) {
            return py::bytes((char*)rsa.GetData(), rsa.DataLen());
        });

        m.attr("MODE_PUBLIC") = py::int_(0);
        m.attr("MODE_PRIVATE") = py::int_(1);

#ifdef VERSION_INFO
    m.attr("__version__") = VERSION_INFO;
#else
    m.attr("__version__") = "dev";
#endif
}