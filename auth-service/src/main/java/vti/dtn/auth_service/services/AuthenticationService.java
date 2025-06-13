package vti.dtn.auth_service.services;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import vti.dtn.auth_service.dto.request.LoginRequest;
import vti.dtn.auth_service.dto.request.RegisterRequest;
import vti.dtn.auth_service.dto.response.LoginResponse;
import vti.dtn.auth_service.dto.response.RegisterResponse;
import vti.dtn.auth_service.entity.UserEntity;
import vti.dtn.auth_service.entity.enums.Role;
import vti.dtn.auth_service.repo.UserRepository;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public RegisterResponse register(RegisterRequest registerRequest) {
        String email = registerRequest.getEmail();
        String userName = registerRequest.getUsername();
        String password = registerRequest.getPassword();
        String role = registerRequest.getRole();
        String firstName = registerRequest.getFirstName();
        String lastName = registerRequest.getLastName();

        Optional<UserEntity> userEntityByEmail = userRepository.findByEmail(email);
        Optional<UserEntity> userEntityByUsername = userRepository.findByUsername(userName);

        if (userEntityByEmail.isPresent() || userEntityByUsername.isPresent()) {
            return RegisterResponse.builder()
                    .status(400)
                    .message("User already exists!")
                    .build();
        }

        UserEntity userEntity = UserEntity.builder()
                .username(userName)
                .firstName(firstName)
                .lastName(lastName)
                .email(email)
                .password(passwordEncoder.encode(password))
                .role(Role.toEnum(role))
                .build();

        userRepository.save(userEntity);

        return RegisterResponse.builder()
                .status(HttpStatus.OK.value())
                .message("User created successfully")
                .build();
    }

    public LoginResponse login(LoginRequest loginRequest) {
        String userName = loginRequest.getUsername();
        String password = loginRequest.getPassword();

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userName, password);
        authenticationManager.authenticate(authenticationToken);

        Optional<UserEntity> userEntityByUsername = userRepository.findByUsername(userName);
        if (userEntityByUsername.isPresent()) {
            UserEntity userEntity = userEntityByUsername.get();
            String accessToken = jwtService.generateAccessToken(userEntity);
            String refreshToken = jwtService.generateRefreshToken(userEntity);

            userEntity.setAccessToken(accessToken);
            userEntity.setRefreshToken(refreshToken);
            userRepository.save(userEntity);

            return LoginResponse.builder()
                    .status(HttpStatus.OK.value())
                    .message("Login successful")
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .userId(userEntity.getId())
                    .build();
        } else {
            return LoginResponse.builder()
                    .status(HttpStatus.UNAUTHORIZED.value())
                    .message("Invalid credentials")
                    .build();
        }
    }


}
