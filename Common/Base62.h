#pragma once

#include <string>
#include <deque>

class Base62Number
{
public:
    Base62Number(unsigned limit = 10);
    Base62Number(unsigned limit, unsigned value);

    Base62Number& operator= (unsigned);
    Base62Number& operator++();

    std::string str() const;

private:
    const unsigned _limit;
    std::deque<char> _body;
};
