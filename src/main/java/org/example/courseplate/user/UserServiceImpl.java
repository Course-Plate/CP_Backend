package org.example.courseplate.user;

import org.example.courseplate.security.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final JwtUtil jwtUtil;

    // @Autowired: Spring이 자동으로 필요한 의존성을 주입합니다.
    @Autowired
    public UserServiceImpl(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder, JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.jwtUtil = jwtUtil;
    }

    // 사용자 회원가입 메서드
    @Override
    public User signup(User user) {
        // 사용자 비밀번호 해싱
        String hashedPassword = bCryptPasswordEncoder.encode(user.getPassword());
        user.setPassword(hashedPassword);

        // 해싱된 비밀번호를 가진 사용자 객체를 데이터베이스에 저장
        return userRepository.save(user);
    }


    //사용자 탈퇴 매서드
    @Override
    public void deleteUser(String userId){
        User user = userRepository.findByUserId(userId);
        if (user != null) {
            userRepository.delete(user);
        } else {
            throw new RuntimeException("유저 아이디가 없습니다.");
        }
    }

    // 사용자 아이디로 사용자 정보를 가져오는 메서드
    @Override
    public User getUserByUserId(String userId) {
        return userRepository.findByUserId(userId);
    }

    // 사용자 로그인 메서드
    @Override
    public String login(String userId, String password) {
        User user = userRepository.findByUserId(userId);
        if (user != null && bCryptPasswordEncoder.matches(password, user.getPassword())) {
            return jwtUtil.generateToken(user.getUserId()); // JWT 발급
        }
        throw new RuntimeException("Invalid credentials");
    }

    // 사용자 아이디가 존재하는지 확인하는 메서드
    @Override
    public boolean isUserIdExist(String userId) {
        User user = userRepository.findByUserId(userId);
        return user != null; // 사용자가 존재하면 true, 아니면 false 반환
    }

    @Override
    public User getUserByPhoneNum(Integer phoneNum) {
        return userRepository.findByPhoneNum(phoneNum);
    }
}