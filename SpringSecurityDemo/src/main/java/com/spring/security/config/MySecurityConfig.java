package com.spring.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import com.spring.security.service.CustomUserDetailService;

@SuppressWarnings("deprecation")
@Configuration
@EnableWebSecurity
//This is used because to enable method based security
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class MySecurityConfig extends WebSecurityConfigurerAdapter{
	/*
	 *  ROLE - High level overview
	 *  NORMAL - read
	 *  ADMIN -read/write/update
	 *  Authoirity - means permission (read,write,update)
	 * */
	
	
	@Autowired
	private CustomUserDetailService customUserDetailService;
	
	
	//Tho enable http basic security
	@Override
	public void configure(HttpSecurity http) throws Exception {
		//csrf is to save from csrf attack if not disable even admin will not able to do create
		http 
		//.csrf().disable()
		//now need to add X-XSRF-TOKEN from client to enable create
		.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
		.and()
			.authorizeRequests()
			//Creating our own page for sign in
			.antMatchers("/signin").permitAll()
			//.antMatchers("/public/home","/public/login","/public/register").permitAll()
			//or
			//.antMatchers("/public/**").permitAll()
			//or can give methods also
			//.antMatchers(HttpMethod.GET,"/public/**").permitAll()
			//.antMatchers("/users/**").hasRole("ADMIN")
			.anyRequest()
			.authenticated()
			.and()
			//This is for Http Basic security configuration
			//.httpBasic();
			//This is for Form Based security
			.formLogin()
			//This is for customized login page
			.loginPage("/signin")
			.loginProcessingUrl("/dologin")
			.defaultSuccessUrl("/users");
	}
	
	//To create our own user
	//This is in memory custom user password
	/*
	 * @Override protected void configure(AuthenticationManagerBuilder auth) throws
	 * Exception { //For normal text password--
	 * //auth.inMemoryAuthentication().withUser("prakhar").password("prakhar").roles
	 * ("NORMAL");
	 * //auth.inMemoryAuthentication().withUser("srasti").password("srasti").roles(
	 * "ADMIN"); //For encoded password--
	 * auth.inMemoryAuthentication().withUser("prakhar").password(this.
	 * passwordEncoder().encode("prakhar")).roles("NORMAL");
	 * auth.inMemoryAuthentication().withUser("srasti").password(this.
	 * passwordEncoder().encode("srasti")).roles("ADMIN"); }
	 */
	
	
	//This is for Database custom user password
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(customUserDetailService).passwordEncoder(passwordEncoder());
	}
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		//To pass password as plain text
		//return NoOpPasswordEncoder.getInstance();
		
		//To pass encoded password
		return new BCryptPasswordEncoder(10);
		
	}
}
