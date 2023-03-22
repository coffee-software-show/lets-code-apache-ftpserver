package bootiful.ftpserver;

import lombok.extern.slf4j.Slf4j;
import org.apache.ftpserver.FtpServer;
import org.apache.ftpserver.FtpServerFactory;
import org.apache.ftpserver.ftplet.*;
import org.apache.ftpserver.listener.ListenerFactory;
import org.apache.ftpserver.usermanager.ClearTextPasswordEncryptor;
import org.apache.ftpserver.usermanager.PropertiesUserManagerFactory;
import org.apache.ftpserver.usermanager.UsernamePasswordAuthentication;
import org.apache.ftpserver.usermanager.impl.ConcurrentLoginPermission;
import org.apache.ftpserver.usermanager.impl.TransferRatePermission;
import org.apache.ftpserver.usermanager.impl.WritePermission;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.util.Assert;

import java.io.File;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;

@SpringBootApplication
public class FtpserverApplication {

    public static void main(String[] args) {
        SpringApplication.run(FtpserverApplication.class, args);
    }

    static UserManager propertiesUserManager() {
        PropertiesUserManagerFactory userManagerFactory = new PropertiesUserManagerFactory();
        userManagerFactory.setFile(new File("/Users/jlong/Downloads/ftpserver/src/main/resources/users.properties"));
        userManagerFactory.setPasswordEncryptor(new ClearTextPasswordEncryptor());
        UserManager userManager = userManagerFactory.createUserManager();
        return userManager;
    }


    static UserManager defaultUserManager() {
        return new DefaultUserManager(ROOT);
    }

    @Bean
    ApplicationRunner ftpService() {
        return args -> {
            FtpServerFactory serverFactory = new FtpServerFactory();
            ListenerFactory factory = new ListenerFactory();
            UserManager userManager = defaultUserManager();
            initUsers(userManager);
            serverFactory.setUserManager(userManager);
            serverFactory.addListener("default", factory.createListener());
            FtpServer server = serverFactory.createServer();
            server.start();
        };
    }

    private static File ROOT = new File("/Users/jlong/Desktop/root");

    private static void initUsers(UserManager userManager) throws Exception {

        for (var userName : Set.of("jlong", "jhoeller", "mbhave")) {
            var user = new DefaultUser(ROOT, userName, "pw", true);
            userManager.save(user);
        }
    }
}

@Slf4j
class DefaultUser implements User {

    private final String username, password;
    private final boolean enabled;
    private final File home;

    /**
     * Copy constructor.
     */
    public DefaultUser(File home, User user) {
        this(home, user.getName(), user.getPassword(), user.getEnabled());
    }

    public DefaultUser(File home, String username, String password, boolean enabled) {
        this.username = username;
        this.password = password;
        this.enabled = enabled;
        this.home = new File(home, username);
        log.debug("the home directory should be " + this.home.getAbsolutePath());
        Assert.state(this.home.exists() || this.home.mkdirs(), "the directory [" + this.home.getAbsolutePath() +
                                                               "] could not be created");
    }

    @Override
    public String getName() {
        return this.username;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public List<? extends Authority> getAuthorities() {
        var rate = 1000 * 1000 * 1000 * 10;
        var authorityList = List.of(new WritePermission(), new ConcurrentLoginPermission(10, 10),
                new TransferRatePermission(rate, rate));
        return authorityList;
    }

    @Override
    public List<? extends Authority> getAuthorities(Class<? extends Authority> clazz) {
        var authorities = getAuthorities(); // .stream().filter(a -> a.getClass().isAssignableFrom(clazz)).toList();
        return authorities;
    }

    static AuthorizationRequest find(Predicate<Authority> filter, List<? extends Authority> authorities, AuthorizationRequest request) {
        var authority = authorities.stream().filter(filter).findAny().orElse(null);
        return null != authority ? request : null;
    }

    @Override
    public AuthorizationRequest authorize(AuthorizationRequest request) {
        return request;
/*
        var authorities = this.getAuthorities();

        if (request instanceof WriteRequest wr)
            return authorities.stream().filter(au -> au instanceof WritePermission).findFirst().map(wp -> request).orElse(null);

        return  List .of(find(au -> au instanceof WritePermission, authorities, request),
                find(au -> au instanceof TransferRatePermission, authorities, request),
                find(au -> au instanceof ConcurrentLoginPermission, authorities, request))
                .stream().filter(au -> au != null).findAny().orElse(null);*/

    }

    @Override
    public int getMaxIdleTime() {
        return 60_000;
    }

    @Override
    public boolean getEnabled() {
        return this.enabled;
    }

    @Override
    public String getHomeDirectory() {
        return  this.home.getAbsolutePath();
    }
}

class DefaultUserManager implements UserManager {

    private final File root;

    private final Map<String, DefaultUser> users = new ConcurrentHashMap<>();

    DefaultUserManager(File root) {
        this.root = root;
    }

    @Override
    public User getUserByName(String username) throws FtpException {
        return this.users.get(username);
    }

    @Override
    public String[] getAllUserNames() throws FtpException {
        return this.users.keySet().toArray(new String[0]);
    }

    @Override
    public void delete(String username) throws FtpException {
        this.users.remove(username);
    }

    @Override
    public void save(User user) throws FtpException {
        Assert.state(user instanceof DefaultUser, "you must use the correct subclass of User for this implementation");
        this.users.put(user.getName(), (DefaultUser) user);
    }

    @Override
    public boolean doesExist(String username) throws FtpException {
        return this.users.containsKey(username);
    }

    @Override
    public User authenticate(Authentication authentication) throws AuthenticationFailedException {
        if (authentication instanceof UsernamePasswordAuthentication pwAuth) {
            var pw = pwAuth.getPassword();
            var username = pwAuth.getUsername();
            var matchingUser = this.users.getOrDefault(username, null);
            if (matchingUser != null) {
                return (matchingUser.getPassword().equals(pw)) ?
                        matchingUser : null;
            }
        }
        throw new AuthenticationFailedException("you screwed up! No FTP for you!");
    }

    @Override
    public String getAdminName() throws FtpException {
        return "";
    }

    @Override
    public boolean isAdmin(String username) throws FtpException {
        return false;
    }
}