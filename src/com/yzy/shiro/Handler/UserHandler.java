package com.yzy.shiro.Handler;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class UserHandler {
	
	@RequestMapping("/login")
	public String login(
			@RequestParam("username") String username,
			@RequestParam("password") String password){
		 // 1. 获取当前的 Subject(和 Shiro 交互的对象), 调用 SecurityUtils.getSubject() 方法. 
        Subject currentUser = SecurityUtils.getSubject();

        // let's login the current user so we can check against roles and permissions:
        //2. 检测当前用户是否 已经被认证. 即是否登录. 调用 Subject 的 isAuthenticated() 方法. 
        if (!currentUser.isAuthenticated()) {
        	//3. 把用户名和密码封装为一个 UsernamePasswordToken 对象. 
            UsernamePasswordToken token = new UsernamePasswordToken(username, password);
            token.setRememberMe(true);
            try {
            	//4. 执行登录. 调用 Subject 的 login(AuthenticationToken). 通常传入的是 UsernamePasswordToken 对象
            	//这也说明 UsernamePasswordToken 是 AuthenticationToken 的实现类. 
                currentUser.login(token);
            }
            //8. 认证时所有异常的父类. 即前面的异常都是该异常的子类. 
            catch (AuthenticationException ae) {
                System.out.println("认证失败"+ae.getMessage());
                return "redirect:/login.jsp";
            }
        }
        return "redirect:/success.jsp";
	}
	
	@RequiresRoles("test")
	@RequestMapping("/testRole")
	public String testAnotation(){
		System.out.println("hello role!!!!");
		return "redirect:/success.jsp";
	}
}
















