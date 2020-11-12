#pragma once

#include "User.h"
#include <vector>

class App
{
public:
	App();
	~App();

public:
	void run();
	void exit();

protected:
	void mainMenu();

	void notLoggedUserMainMenu();
	void loggedAdminUserMainMenu();
	void loggedNotAdminUserMainMenu();

	void login();
	void logout();
	void changePassword();
	void listUsers();

    void blockUser();
    void unblockUser();
    void enableCheckUserPassword();
    void disableCheckUserPassword();
	void enableAdminUser();
	void disableAdminUser();
    void createNewUser();
	void about();

protected:
	void readUsers();
	void writeUsers();

protected:
	bool hasUser( const std::string & _userLogin ) const;
	User & getUser( const std::string & _userLogin );
	User & getLoggedUser();

	bool checkPassword( const std::string & _pass ) const;
	bool checkIsBruteForce() const;
	int getRemainingLoginAttemptsNumber() const;

private:
	bool m_isRunned;

private:
	int32_t m_countLoginFail;
	std::string m_loggedUserName;
	std::vector<User> m_users;
};
