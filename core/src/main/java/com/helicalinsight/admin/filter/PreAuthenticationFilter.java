/**
 *    Copyright (C) 2013-2019 Helical IT Solutions (http://www.helicalinsight.com) - All rights reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package com.helicalinsight.admin.filter;

import com.helicalinsight.auth.customAuth.CipherUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.regex.Pattern;

/**
 * This is sub class of spring framework's UsernamePasswordAuthenticationFilter,
 * this class is get invoked when user submit the form using his/her
 * credentials from login page, this class is responsible for whether user login
 * along with user name and password it combine user name and
 * UserDetailsServiceImpl in service layer for authentication.
 *
 * @author Muqtar Ahmed
 */
public class PreAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private static final Logger logger = LoggerFactory.getLogger(PreAuthenticationFilter.class);


    /**
     * override method which takes HttpServletRequest and HttpServletResponse
     * arguments and bypass it to super class
     */

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws
            AuthenticationException {
        
        //the below code decrypts the encrypted j_username
        if ( request.getParameter("j_username").length()>20) {
            String authTokenUser = null;
            String authTokenPass = null;
            final String encryptedToken = request.getParameter("j_username");
            final String token = CipherUtils.decrypt(encryptedToken);
            final String[] userDetailsParams = token.split(Pattern.quote("|"));
            for (int i = 0; i < userDetailsParams.length; ++i) {
                final String[] detail = userDetailsParams[i].split(Pattern.quote("="));
                if (detail[0].equalsIgnoreCase("username") && detail.length == 2) {
                    authTokenUser = detail[1];
                }
                else if (detail[0].equalsIgnoreCase("password") && detail.length == 2) {
                    authTokenPass = detail[1];
                }
            }
            UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(authTokenUser, authTokenPass);
            logger.debug(authTokenUser + " is authenticated ? " +  authRequest.isAuthenticated());
            setDetails(request, authRequest);
            return this.getAuthenticationManager().authenticate(authRequest);
        }
        //End decrypting the username

        logger.debug("Attempting for authentication. " + "j_username = " + request.getParameter("j_username") + ", " +
                "j_password = [*****]");
        return super.attemptAuthentication(request, response);
    }

    /**
     * override method which takes HttpServletRequest argument get the request
     * parameters from login page
     *
     * @return String combine user name
     */

    @Override
    protected String obtainUsername(HttpServletRequest request) {
        String username = request.getParameter(getUsernameParameter());
        String combinedUsername;
        combinedUsername = username;
        return combinedUsername;
    }


}
