package br.com.rafaelsouza.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.rafaelsouza.todolist.user.IUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    private IUserRepository userRepository;

    @Override
    public void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
        throws ServletException, IOException {
            var servletPath = req.getServletPath();
            if(servletPath.startsWith("/tasks/")){
                var authorization = req.getHeader("Authorization");
                var authEncoded = authorization.substring("Basic".length()).trim();
                byte [] authDecode = Base64.getDecoder().decode(authEncoded);
                var authString = new String(authDecode);
                String[] credentials = authString.split(":");
    
                String username = credentials[0];
                String password = credentials[1];
    
                var user = this.userRepository.findByUsername(username);
                if(user == null){
                    res.sendError(401, "Usuario sem autorizaçao");
                }else{
                    var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
                    if(passwordVerify.verified){
                        req.setAttribute("idUser", user.getId());
                        chain.doFilter(req, res);
                    }else{
                        res.sendError(401, "Usuario sem autorizaçao");
                    }
                }
            }else{
                chain.doFilter(req, res);
            }
        }
}
