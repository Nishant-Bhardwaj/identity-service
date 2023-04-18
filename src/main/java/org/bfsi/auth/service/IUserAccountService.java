package org.bfsi.auth.service;

import org.bfsi.auth.entity.UserAccount;

import java.util.List;
import java.util.Optional;

public interface IUserAccountService {

    boolean saveUser(UserAccount user);

    Optional<UserAccount> findUserByUserName(String userName);

    List<UserAccount> findAllUsers();
}
