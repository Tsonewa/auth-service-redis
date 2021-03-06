package com.example.authenticationservice.domain;

import lombok.Data;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

// Content a session user information -> username, password and calculate if
// its logged in and validate the session
@Data
public class SessionUser {

    private String username;
    private String password;
    private Date created;

    public boolean hasExpired() {
        if(created == null){
            return true;
        }
        LocalDateTime localDateTime = created.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
        localDateTime = localDateTime.plusHours(1);
        return  Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant()).before(new Date());
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Date getCreated() {
        return created;
    }

    public void setCreated(Date created) {
        this.created = created;
    }
}
