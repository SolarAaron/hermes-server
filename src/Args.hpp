//
// Created by atorres on 3/9/25.
//

#ifndef ARGS_HPP
#define ARGS_HPP

namespace slr::hermes{
class Args {
public:
    bool check_sanity;
    Args();
    Args& parse(int argc, char** argv);
};
}


#endif //ARGS_HPP
