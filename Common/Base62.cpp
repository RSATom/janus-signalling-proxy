#include "Base62.h"

#include <cstring>

enum {
    DECODE_MIN_CHAR = '0',
    DECODE_OFFSET = '0',
};

static const char Alphabet[] =
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char DecAlphabet[] =
    "0123456789       TUVWXYZ[\\]^_`abcdefghijklm      :;<=>?@ABCDEFGHIJKLMNOPQRS";

Base62Number::Base62Number(unsigned limit) :
    _limit(limit)
{
}

Base62Number::Base62Number(unsigned limit, unsigned value) :
    Base62Number(limit)
{
    *this = value;
}

Base62Number& Base62Number::operator= (unsigned value)
{
    const unsigned base = (sizeof(Alphabet) - 1);

    _body.clear();

    while(value > base - 1) {
        if(_body.size() >= _limit)
            break;

        const unsigned digit = value % base;
        _body.push_front(Alphabet[digit]);
        value /= base;
    }

    if(_body.size() < _limit) {
        const unsigned digit = value;
        _body.push_front(Alphabet[digit]);
    }

    return *this;
}

Base62Number& Base62Number::operator++()
{
    if(_body.empty())
        _body.push_front(Alphabet[0]);
    else{
        for(unsigned offset = 0; offset < _body.size() + 1; ++offset) {
            if(offset == _body.size()) {
                if(_body.size() >= _limit)
                    _body.assign(1, Alphabet[0]);
                else
                    _body.push_front(Alphabet[1]);
                break;
            }

            const unsigned pos = static_cast<unsigned>(_body.size()) - offset - 1;
            if(_body[pos] == Alphabet[sizeof(Alphabet) - 1 - 1]) {
                _body[pos] = Alphabet[0];
            } else {
                const int digit = DecAlphabet[_body[pos] - DECODE_OFFSET] - DECODE_MIN_CHAR;
                _body[pos] = Alphabet[digit + 1];
                break;
            }
        }
    }

    return *this;
}

std::string&& Base62Number::str() const
{
    return std::move(std::string(_body.begin(), _body.end()));
}
