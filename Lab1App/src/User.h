#pragma once

#include <string>

class User
{
public:
    User();
    ~User();

public:
    std::string getLogin() const;
    void setLogin( const std::string & _login );

    std::string getPassword() const;
    void setPassword( const std::string & _password );

    bool getIsAdmin() const;
    void setIsAdmin( bool _value );

    bool getIsBlocked() const;
    void setIsBlocked( bool _value );

    bool getIsPasswordCheck() const;
    void setIsPasswordCheck( bool _value );

public:
    std::string toString() const;

private:
    std::string m_login;
    std::string m_password;
    bool m_isAdmin;
    bool m_isBlocked;
    bool m_isPasswordCheck;
};