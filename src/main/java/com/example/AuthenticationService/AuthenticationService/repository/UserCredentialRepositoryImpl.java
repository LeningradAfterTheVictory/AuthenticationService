package com.example.AuthenticationService.AuthenticationService.repository;

import com.example.AuthenticationService.AuthenticationService.entity.UserCredential;
import com.example.AuthenticationService.AuthenticationService.entity.UserCredentialDTO;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;

import java.sql.*;
import java.util.Optional;

@Repository
public class UserCredentialRepositoryImpl implements UserCredentialRepository {
    @Value("${spring.datasource.url}")
    private String url;

    @Value("${spring.datasource.username}")
    private String user;

    @Value("${spring.datasource.password}")
    private String password;

    public Optional<UserCredential> findByNameOrEmail(String name) {
        String query = "SELECT * FROM users WHERE name = ? OR mail = ?";

        try (Connection conn = DriverManager.getConnection(url, user, password);
             PreparedStatement stmt = conn.prepareStatement(query)) {
            stmt.setObject(1, name);
            stmt.setObject(2, name);

            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                UserCredential userCredential = new UserCredential();
                userCredential.setId(rs.getLong("id"));
                userCredential.setName(rs.getString("name"));
                userCredential.setEmail(rs.getString("mail"));
                userCredential.setPassword(rs.getString("password"));
                return Optional.of(userCredential);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return Optional.empty();
    }

    public Long save(UserCredentialDTO userCredential) {
        String query = "INSERT INTO users (name, mail, password, role) VALUES (?, ?, ?, 'USER') RETURNING id";
        String queryCheck = "SELECT * FROM users WHERE name=?";
        try (Connection conn = DriverManager.getConnection(url, user, password);
             PreparedStatement stmt = conn.prepareStatement(query, Statement.RETURN_GENERATED_KEYS)) {
            if(findUser(queryCheck, userCredential.getName()).isPresent()) {
                return -1L;
            }

            stmt.setString(1, userCredential.getName());
            stmt.setString(2, userCredential.getEmail());
            stmt.setString(3, userCredential.getPassword());
            stmt.executeUpdate();

            ResultSet rs = stmt.getGeneratedKeys();
            if (rs.next()) {
                return rs.getLong("id");
            }

        } catch (SQLException e) {
            e.printStackTrace();
        }
        return -1L;
    }

    private Optional<UserCredential> findUser(String query, Object param) {
        try (Connection conn = DriverManager.getConnection(url, user, password);
             PreparedStatement stmt = conn.prepareStatement(query)) {
            stmt.setObject(1, param);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                UserCredential userCredential = new UserCredential();
                userCredential.setId(rs.getLong("id"));
                userCredential.setName(rs.getString("name"));
                userCredential.setEmail(rs.getString("mail"));
                userCredential.setPassword(rs.getString("password"));
                return Optional.of(userCredential);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return Optional.empty();
    }
}
