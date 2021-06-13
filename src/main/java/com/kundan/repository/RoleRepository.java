package com.kundan.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.kundan.model.ERole;
import com.kundan.model.Role;

public interface RoleRepository extends JpaRepository<Role, Long> {
	
	Optional<Role> findByName(ERole name);
}
