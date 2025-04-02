package com.example.users.Repository;


import com.example.users.Entity.MfaInfo;
import com.example.users.Entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface MfaInfoRepository extends JpaRepository<MfaInfo, Long> {
    Optional<MfaInfo> findByUser(User user);
}