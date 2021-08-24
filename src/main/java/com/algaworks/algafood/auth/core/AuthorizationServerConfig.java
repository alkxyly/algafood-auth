package com.algaworks.algafood.auth.core;

import java.util.Arrays;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter{
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private UserDetailsService detailsService;
	
	@Autowired
	private JwtKeyStoreProperties jwtKeyStoreProperties;
	
	@Autowired
	private DataSource dataSource;
	
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		
		clients.jdbc(dataSource);
		
//		clients.inMemory()
//			.withClient("algafood-web")
//				.secret(passwordEncoder.encode("web123"))
//				.authorizedGrantTypes("password","refresh_token")
//				.scopes("WRITE","READ")
//				.accessTokenValiditySeconds(6 * 60 * 60)
//				.refreshTokenValiditySeconds(60 * 24 * 60 * 60)
//			.and()
//				.withClient("foodanalytics")
//				.secret(passwordEncoder.encode("food123"))
//				.authorizedGrantTypes("authorization_code")
//				.scopes("WRITE", "READ")
//				.redirectUris("http://aplicacao-cliente")
//			.and()
//				.withClient("faturamento")
//				.secret(passwordEncoder.encode("faturamento123"))
//				.authorizedGrantTypes("client_credentials")
//				.scopes("WRITE", "READ")
//			.and()
//				.withClient("webadmin")
//				.authorizedGrantTypes("implicit")
//				.redirectUris("http://aplicacao-cliente")
//				.scopes("WRITE", "READ")
//			.and()
//				.withClient("checktoken")
//				.secret(passwordEncoder.encode("check123"));
	}
	
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		security.checkTokenAccess("permitAll()")
				.tokenKeyAccess("permitAll()")
				.allowFormAuthenticationForClients();
//				.allowFormAuthenticationForClients();
	}
	
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		
		var enhancerChain =  new TokenEnhancerChain();
		enhancerChain.setTokenEnhancers(
				Arrays.asList(new JwtCustomClaimsTokenEnhancer(),
							  jwtAceAccessTokenConverter()));
		
		endpoints
			.authenticationManager(authenticationManager)
			.userDetailsService(detailsService)
			.reuseRefreshTokens(false)
			.accessTokenConverter(jwtAceAccessTokenConverter())
			.tokenEnhancer(enhancerChain)
			.approvalStore(tokenStore(endpoints.getTokenStore()))
			.tokenGranter(tokenGranter(endpoints));
	}
	
	private ApprovalStore tokenStore(TokenStore tokenStore) {
		var approvalStore = new TokenApprovalStore();
		approvalStore.setTokenStore(tokenStore);
		return approvalStore;
	}
	
	@Bean
	public JwtAccessTokenConverter jwtAceAccessTokenConverter() {
		var jwtAccessTokenConverter =  new JwtAccessTokenConverter();
		
		var jksResource = new ClassPathResource(jwtKeyStoreProperties.getPath());

		var keyStoreKeyFactory = new KeyStoreKeyFactory(jksResource, jwtKeyStoreProperties.getPassword().toCharArray());
		var keyPair = keyStoreKeyFactory.getKeyPair(jwtKeyStoreProperties.getKeypairAlias());
		
		jwtAccessTokenConverter.setKeyPair(keyPair);
		
		return jwtAccessTokenConverter;
	}
	
	private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {
		var pkceAuthorizationCodeTokenGranter = new PkceAuthorizationCodeTokenGranter(endpoints.getTokenServices(),
				endpoints.getAuthorizationCodeServices(), endpoints.getClientDetailsService(),
				endpoints.getOAuth2RequestFactory());
		
		var granters = Arrays.asList(
				pkceAuthorizationCodeTokenGranter, endpoints.getTokenGranter());
		
		return new CompositeTokenGranter(granters);
	}
	
}
