package org.bfsi.auth.serviceImpl;

import lombok.AllArgsConstructor;
import org.bfsi.auth.entity.UserAccount;
import org.bfsi.auth.repository.UserAccountRepository;
import org.bfsi.auth.service.IUserAccountService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@AllArgsConstructor
public class UserAccountServiceImpl implements IUserAccountService {

    UserAccountRepository userRepository;
    PasswordEncoder passwordEncoder;

    @Override
    public boolean saveUser(UserAccount userDto) {
        UserAccount user = new UserAccount();
        user.setUserName(userDto.getUserName());
        user.setPassword(passwordEncoder.encode(userDto.getPassword()));
        UserAccount savedUser = userRepository.save(user);

        return (savedUser.getId() > 0);
    }

    @Override
    public Optional<UserAccount> findUserByUserName(String userName) {
        return userRepository.findByUserName(userName);
    }

    @Override
    public List<UserAccount> findAllUsers() {
        return null;
    }
}
