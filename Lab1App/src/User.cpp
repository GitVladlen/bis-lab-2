#include "User.h"

#include <sstream>

User::User()
    : m_isAdmin( false )
    , m_isBlocked( false )
    , m_isPasswordCheck( true )
{
}

User::~User()
{
}

std::string User::getLogin() const
{
    return m_login;
}

void User::setLogin( const std::string & _login )
{
    m_login = _login;
}

std::string User::getPassword() const
{
    return m_password;
}

void User::setPassword( const std::string & _password )
{
    m_password = _password;
}

bool User::getIsAdmin() const
{
    return m_isAdmin;
}

void User::setIsAdmin( bool _value )
{
    m_isAdmin = _value;
}

bool User::getIsBlocked() const
{
    return m_isBlocked;
}

void User::setIsBlocked( bool _value )
{
    m_isBlocked = _value;
}

bool User::getIsPasswordCheck() const
{
    return m_isPasswordCheck;
}

void User::setIsPasswordCheck( bool _value )
{
    m_isPasswordCheck = _value;
}

std::string User::toString() const
{
    std::stringstream ss;

    ss << this->getLogin() << " ";
    ss << this->getPassword() << " ";
    ss << this->getIsAdmin() << " ";
    ss << this->getIsBlocked() << " ";
    ss << this->getIsPasswordCheck() << " ";

    return ss.str();
}
