package com.neu.Bean;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.config.Ini;
import org.apache.shiro.config.IniFactorySupport;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import java.security.Security;


public class HelloWorld {
    private static final Logger log = LoggerFactory.getLogger(com.neu.Bean.HelloWorld.class);

    public static void main(String arg[]) {
        log.info("Testing log4j.....");
        //获取SecurityManager
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");
        SecurityManager securityManager = factory.getInstance();
        //设置安全管理器
        SecurityUtils.setSecurityManager(securityManager);

        //创建用户
        Subject currentUser = SecurityUtils.getSubject();
        Session session = currentUser.getSession();

        session.setAttribute("name","梁俊杰");

        String value = (String)session.getAttribute("name");
        if(value != null){
            log.info("Session的值为："+ value);
        }

        if(currentUser.isAuthenticated() == false){
            UsernamePasswordToken token = new UsernamePasswordToken("presidentskroob","12345");
            token.setRememberMe(true);
            try{
                currentUser.login(token);
                log.info("用户名和密码正确！登录成功");
            }catch(UnknownAccountException e){
                log.info("账户不存在");
            }catch(IncorrectCredentialsException e){
                log.info("密码错误");
            }catch(LockedAccountException e){
                log.info("用户已被锁死");
            }catch(AuthenticationException e){
                log.info("认证异常");
            }
        }

        if(currentUser.hasRole("goodguy1")){
            log.info("用户拥有该角色");
        }else{
            log.info("用户没有该角色");
        }

        if(currentUser.isPermitted("winnebago:drive:eagle51")){
            log.info("用户拥有该权限");
        }else {
            log.info("用户没有该权限");
        }

        currentUser.logout();
        System.exit(0);
    }
}
