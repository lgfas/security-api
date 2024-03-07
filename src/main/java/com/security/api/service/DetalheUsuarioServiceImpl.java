package com.security.api.service;

import com.security.api.data.DetalheUsuarioData;
import com.security.api.model.UsuarioModel;
import com.security.api.repository.UsuarioRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class DetalheUsuarioServiceImpl implements UserDetailsService {

    private final UsuarioRepository usuarioRepository;

    public DetalheUsuarioServiceImpl(UsuarioRepository usuarioRepository) {
        this.usuarioRepository = usuarioRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Optional<UsuarioModel> usuarioModel = usuarioRepository.findByLogin(username);

        if (usuarioModel.isEmpty()) {
            throw new UsernameNotFoundException("Usuário [" + username + "] não encontrado!");
        }

        return new DetalheUsuarioData(usuarioModel);
    }
}
