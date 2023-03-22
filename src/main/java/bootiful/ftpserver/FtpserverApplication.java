package bootiful.ftpserver;

import org.apache.ftpserver.FtpServer;
import org.apache.ftpserver.FtpServerFactory;
import org.apache.ftpserver.ftplet.UserManager;
import org.apache.ftpserver.listener.ListenerFactory;
import org.apache.ftpserver.usermanager.ClearTextPasswordEncryptor;
import org.apache.ftpserver.usermanager.PropertiesUserManagerFactory;
import org.apache.ftpserver.usermanager.impl.BaseUser;
import org.apache.ftpserver.usermanager.impl.WritePermission;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.io.File;
import java.util.List;
import java.util.Set;

@SpringBootApplication
public class FtpserverApplication {

    public static void main(String[] args) {
        SpringApplication.run(FtpserverApplication.class, args);
    }

    @Bean
    ApplicationRunner ftpService() {
        return args -> {
            FtpServerFactory serverFactory = new FtpServerFactory();
            ListenerFactory factory = new ListenerFactory();
            PropertiesUserManagerFactory userManagerFactory = new PropertiesUserManagerFactory();
            userManagerFactory.setFile(new File("/Users/jlong/Downloads/ftpserver/src/main/resources/users.properties"));
            userManagerFactory.setPasswordEncryptor(new ClearTextPasswordEncryptor());
            UserManager userManager = userManagerFactory.createUserManager();
            initUsers(userManager);
            serverFactory.setUserManager(userManager);
            serverFactory.addListener("default", factory.createListener());
            FtpServer server = serverFactory.createServer();
            server.start();
        };
    }

    private static void initUsers(UserManager userManager) throws Exception {
        var root = new File("/Users/jlong/Desktop/root");
        for (var userName : Set.of("jlong", "jhoeller", "mbhave")) {
            var user = new BaseUser();
            user.setEnabled(true);
            user.setName(userName);
            user.setPassword("pw");
            user.setAuthorities(List.of(new WritePermission()));
            user.setHomeDirectory(root.getAbsolutePath());
            userManager.save(user);
        }
    }
}
