package com.kundan.util;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.kundan.model.ERole;
import com.kundan.model.Role;
import com.kundan.repository.RoleRepository;

@Component
public class RolesUtils {

	@Autowired
	private RoleRepository roleRepository;

	public void mapRoles(Set<String> userRoles,Set<Role> dbRoles) {
		
		if (userRoles == null) {
			Role userRole = roleRepository.findByName(ERole.ROLE_USER)
					.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
			dbRoles.add(userRole);
			
		} else {
			userRoles.forEach(role -> {
				switch (role) {
				case "admin":
					Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
					.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					dbRoles.add(adminRole);
					break;
				case "mod":
					Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
					.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					dbRoles.add(modRole);
					break;
				default:
					Role userRole = roleRepository.findByName(ERole.ROLE_USER)
					.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					dbRoles.add(userRole);
				}
			});
		}
	}
}
