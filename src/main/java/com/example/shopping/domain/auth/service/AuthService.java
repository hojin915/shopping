package com.example.shopping.domain.auth.service;

import com.example.shopping.config.JwtUtil;
import com.example.shopping.config.PasswordEncoder;
import com.example.shopping.domain.auth.dto.request.LoginRequestDto;
import com.example.shopping.domain.auth.dto.request.SignupRequestDto;
import com.example.shopping.domain.auth.dto.request.WithdrawRequestDto;
import com.example.shopping.domain.auth.dto.response.LoginResponseDto;
import com.example.shopping.domain.auth.dto.response.SignupResponseDto;
import com.example.shopping.domain.auth.dto.response.WithdrawResponseDto;
import com.example.shopping.domain.user.entity.User;
import com.example.shopping.domain.user.enums.UserRole;
import com.example.shopping.domain.user.repository.UserRepository;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    // 예외처리 수정
    @Transactional
    public SignupResponseDto signup(@Valid SignupRequestDto request) {
        if(userRepository.existsByEmail(request.getEmail())){
            throw new RuntimeException("Email already in use");
        }

        String encodedPassword = passwordEncoder.encode(request.getPassword());

        UserRole userRole = UserRole.of(request.getUserRole());

        User user = new User(
                request.getEmail(),
                encodedPassword,
                request.getName(),
                request.getAddress(),
                userRole
        );
        User savedUser = userRepository.save(user);

        return new SignupResponseDto(savedUser);
    }

    @Transactional
    public WithdrawResponseDto withdraw(@Valid WithdrawRequestDto request) {
        User user = userRepository.findById(1L)
                .orElseThrow(() -> new RuntimeException("User not found"));
        if(!passwordEncoder.matches(request.getPassword(), user.getPassword())){
            throw new RuntimeException("Wrong password");
        }

        userRepository.delete(user);

        return new WithdrawResponseDto("회원 탈퇴가 완료되었습니다");
    }

    @Transactional(readOnly = true)
    public LoginResponseDto login(@Valid LoginRequestDto request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("User not found"));
        if(!passwordEncoder.matches(request.getPassword(), user.getPassword())){
            throw new RuntimeException("Wrong password");
        }

        String token = jwtUtil.createToken(user.getId(), user.getEmail(), user.getUserRole());

        return new LoginResponseDto(user.getId(), user.getEmail(), token);
    }


    // 리프레시 토큰 이용한 구현 예정
    public void logout(User user) {
        System.out.println(user.getId());
    }
}
