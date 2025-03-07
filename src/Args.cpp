//
// Created by atorres on 3/9/25.
//

#include "Args.hpp"

#include <string>

slr::hermes::Args::Args(): check_sanity(false) {}

slr::hermes::Args&
slr::hermes::Args::parse(int argc, char** argv) {
    for(int arg = 1; arg < argc; arg++) {
        if(std::string(argv[arg]) == "-s") {
            check_sanity = true;
        }
    }

    return *this;
}
