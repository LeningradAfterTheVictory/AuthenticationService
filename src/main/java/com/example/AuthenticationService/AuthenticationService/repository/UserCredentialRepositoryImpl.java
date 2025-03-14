package com.example.AuthenticationService.AuthenticationService.repository;

import com.example.AuthenticationService.AuthenticationService.entity.UserCredential;
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

    public Optional<UserCredential> findByName(String name) {
        String query = "SELECT * FROM users WHERE name = ?";
        return findUser(query, name);
    }

    public Optional<UserCredential> findById(Long id) {
        String query = "SELECT * FROM users WHERE id = ?";
        return findUser(query, id);
    }

    public Optional<UserCredential> findByEmail(String email) {
        String query = "SELECT * FROM users WHERE mail = ?";
        return findUser(query, email);
    }

    public String save(UserCredential userCredential) {
        String query = "INSERT INTO users (name, mail, password, role) VALUES (?, ?, ?, 'USER') RETURNING id";
        String queryCheck = "SELECT * FROM users WHERE name=?";
        try (Connection conn = DriverManager.getConnection(url, user, password);
             PreparedStatement stmt = conn.prepareStatement(query, Statement.RETURN_GENERATED_KEYS)) {
            if(findUser(queryCheck, userCredential.getName()).isPresent()) {
                return "Fail";
            }

            stmt.setString(1, userCredential.getName());
            stmt.setString(2, userCredential.getEmail());
            stmt.setString(3, userCredential.getPassword());
            stmt.executeUpdate();

            ResultSet rs = stmt.getGeneratedKeys();
            if (rs.next()) {
                userCredential.setId(rs.getInt(1));
            }

            return "Success";
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return "Fail";
    }

    public String getRoleForUser(String userName) {
        String query = "SELECT role FROM users WHERE name=?";
        try (Connection conn = DriverManager.getConnection(url, user, password);
             PreparedStatement stmt = conn.prepareStatement(query)) {
            stmt.setString(1, userName);

            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getString("role");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }

        return "No role";
    }

    private Optional<UserCredential> findUser(String query, Object param) {
        try (Connection conn = DriverManager.getConnection(url, user, password);
             PreparedStatement stmt = conn.prepareStatement(query)) {
            stmt.setObject(1, param);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                UserCredential userCredential = new UserCredential();
                userCredential.setId(rs.getInt("id"));
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
