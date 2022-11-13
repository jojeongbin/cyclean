package com.example.demo.controller;

import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletResponse;
import java.util.List;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/account")
@Slf4j
public class AccountController {

    private final UserRepository userRepository;

    private final BCryptPasswordEncoder passwordEncoder;

//    private final JwtProcessor jwtProcessor;

    @GetMapping("/login")
    public ModelAndView login() {
        ModelAndView modelAndView = new ModelAndView("account/login");
        return modelAndView;
    }

    // register 조회
    @GetMapping("/register")
    public ModelAndView register() {
        ModelAndView modelAndView = new ModelAndView("account/register");
        return modelAndView;
    }


    // postmapping 수정해야 됨
    // localhost8080/account/login 했을 시 body에 토큰 값 넘겨주기
    // HttpServletResponse response, Authentication authResult
    @PostMapping("/login")
    public String login(@RequestBody Map<String, String> users){
        User user = userRepository.findByUsername(users.get("username"))
                .orElseThrow(() -> new IllegalArgumentException("가입되지 않은 username입니다."));
        if (!passwordEncoder.matches(users.get("password"), user.getPassword())){
            throw new IllegalStateException("잘못된 비밀번호 입니다.");
        }
//        UserAccount userAccount = (UserAccount) authResult.getPrincipal();
//        String jwtToken = jwtProcessor.createJwtToken(userAccount);
//        response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + " " + jwtToken);
        return user.toString() + "\n 로그인이 되었습니다.";
    }

    // register 값 넣기
    @PostMapping("/register")
    @ResponseBody
    public String register(@RequestBody User user){
        String rawPassword = user.getPassword();
        String encPassword = passwordEncoder.encode(rawPassword);
        user.setPassword(encPassword);
        user.setRole("USER");
        userRepository.save(user);
        return user.toString() + " \n 회원가입이 완료되었습니다.";
    }

    // user 권한을 가진 사용자가 들어갈 수 있은 시범용
    @GetMapping("api/user")
    @ResponseBody
    public String user(){
        // user 확인용
        return "user 권한이 있습니다.";
    }

    // 정보가 잘 저장되었는지 확인하는 시범용
    @GetMapping("/users")
    public List<User> users() {
        return userRepository.findAll();
    }
}

