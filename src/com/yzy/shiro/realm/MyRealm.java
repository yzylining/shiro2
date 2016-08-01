package com.yzy.shiro.realm;

import java.util.HashSet;
import java.util.Set;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

public class MyRealm extends AuthorizingRealm{
	/**
	 * 用于授权的 realm 的回调方法. 
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(
			PrincipalCollection principals) {
		Object principal = principals.getPrimaryPrincipal();
		System.out.println(principal+"--------------------");
		Set<String> roles = new HashSet<>();
		roles.add("bcde");
		if ("admin".equals(principal)) {
			roles.add("admin");
			roles.add("test");
		}
		
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo(roles);
		return info;
	}
	
	/**
	 * 用于认证的 realm 的回调方法.
	 * 参数 AuthenticationToken
	 * 即为登录时调用 Subject 的 login(AuthenticationToken) 方法时传入的参数
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(
			AuthenticationToken token) throws AuthenticationException {
		UsernamePasswordToken userToken = (UsernamePasswordToken) token;
		//2. 从令牌中获取页面传递过来的用户名
		String username = userToken.getUsername();
		//3. 利用 username 查询数据表, 获取用户的信息
		System.out.println("从数据库中根据"+username+"来查询user对象信息");
		// 认证成功后的实体信息，可以是username,也可以是一个对象
		Object principal = username;
//		Object credentials = "123123";
		//从数据库中查出的加密数据
		Object hashedCredentials = null;
		if ("admin".equals(username)) {
			hashedCredentials = "336a2c235a6b84c43c7dff86f67fa5c9";
		}else if ("bcde".equals(username)) {
			hashedCredentials = "e8cc54f5d5e4b7e4441fca2b93e43378";
		}
		//在实际应用中,盐值从数据库查出,盐值是随机生成的
		String salt = username;
		ByteSource credentialsSalt = ByteSource.Util.bytes(salt);
		//通过父类的getName方法，获得realmName
		String realmName = getName();
		System.out.println(realmName);
		SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(principal, hashedCredentials, credentialsSalt, realmName);
		return info;
	}

}
