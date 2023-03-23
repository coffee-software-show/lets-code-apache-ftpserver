package bootiful.ftpserver;

import lombok.extern.slf4j.Slf4j;
import org.apache.ftpserver.FtpServer;
import org.apache.ftpserver.FtpServerFactory;
import org.apache.ftpserver.ftplet.*;
import org.apache.ftpserver.listener.ListenerFactory;
import org.apache.ftpserver.usermanager.UsernamePasswordAuthentication;
import org.apache.ftpserver.usermanager.impl.*;
import org.apache.mina.transport.socket.nio.NioProcessor;
import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ImportRuntimeHints;
import org.springframework.context.event.EventListener;
import org.springframework.core.io.ClassPathResource;
import org.springframework.integration.core.GenericHandler;
import org.springframework.integration.dsl.IntegrationFlow;
import org.springframework.integration.dsl.MessageChannels;
import org.springframework.integration.event.inbound.ApplicationEventListeningMessageProducer;
import org.springframework.integration.ftp.server.ApacheMinaFtpEvent;
import org.springframework.integration.ftp.server.ApacheMinaFtplet;
import org.springframework.integration.ftp.server.SessionClosedEvent;
import org.springframework.integration.ftp.server.SessionOpenedEvent;
import org.springframework.messaging.MessageChannel;
import org.springframework.util.Assert;
import org.springframework.util.unit.DataSize;

import java.io.File;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@SpringBootApplication
@ImportRuntimeHints(FtpserverApplication.Hints.class)
@EnableConfigurationProperties(FtpserverApplication.FtpProperties.class)
public class FtpserverApplication {

    @ConfigurationProperties("ftp")
    record FtpProperties(File root, Duration idleTime, int concurrentUsers, DataSize rate) {
    }

    static class Hints implements RuntimeHintsRegistrar {

        @Override
        public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
            Set.of(NioProcessor.class).forEach(s -> hints.reflection().registerType(s, MemberCategory.values()));
            hints.resources().registerResource(new ClassPathResource("org/apache/ftpserver/message/FtpStatus.properties"));
        }
    }

    @Bean
    MessageChannel eventsChannel() {
        return MessageChannels.direct().get();
    }

    @Bean
    ApacheMinaFtplet apacheMinaFtplet() {
        return new ApacheMinaFtplet();
    }

    @Bean
    IntegrationFlow ftpServerIntegrationFlow(MessageChannel eventsChannel) {
        return IntegrationFlow
                .from(eventsChannel)
                .handle((GenericHandler<ApacheMinaFtpEvent>) (apacheMinaFtpEvent, messageHeaders) -> {
                    log.info("new event: " + apacheMinaFtpEvent.getClass().getName() + ':' + apacheMinaFtpEvent.getSession());
                    return null;
                })
                .get();
    }

    @Bean
    ApplicationEventListeningMessageProducer applicationEventListeningMessageProducer() {
        var producer = new ApplicationEventListeningMessageProducer();
        producer.setEventTypes(ApacheMinaFtpEvent.class);
        producer.setOutputChannel(eventsChannel());
        return producer;
    }

    @EventListener
    void sessionOpened(SessionOpenedEvent sessionOpenedEvent) {
        log.info("session opened! " + sessionOpenedEvent.getSession().getClientAddress());
    }

    @EventListener
    void sessionClosed(SessionClosedEvent sessionClosedEvent) {
        log.info("session closed! " + sessionClosedEvent.getSession().getClientAddress());
    }


    public static void main(String[] args) {
        SpringApplication.run(FtpserverApplication.class, args);
    }

    @Bean
    DefaultUserManager defaultUserManager(FtpProperties properties) throws Exception {
        var udm = new DefaultUserManager();
        for (var userName : Set.of("jlong", "dcarter", "jhoeller", "mbhave")) {
            var user = new DefaultUser(properties.root(), userName, "pw", true,
                    properties.concurrentUsers(),
                    properties.rate.toBytes(),
                    (int) properties.idleTime().toSeconds());
            udm.save(user);
        }
        return udm;
    }

    @Bean
    FtpServer ftpServer(Map<String, Ftplet> ftpletMap, UserManager userManager) throws Exception {
        FtpServerFactory serverFactory = new FtpServerFactory();
        ListenerFactory factory = new ListenerFactory();
        serverFactory.setUserManager(userManager);
        serverFactory.setFtplets(ftpletMap);
        serverFactory.addListener("default", factory.createListener());
        return serverFactory.createServer();
    }

    @Bean
    DisposableBean destroysFtpServer(FtpServer ftpServer) {
        return ftpServer::stop;
    }

    @Bean
    InitializingBean startsFtpServer(FtpServer ftpServer) {
        return ftpServer::start;
    }

}

@Slf4j
class DefaultUser implements User {

    private final String username, password;
    private final boolean enabled;
    private final File home;
    private final long rateInBytes;
    private final int concurrentLogins;
    private final int idleTimeInSeconds;

    public DefaultUser(File home, String username, String password, boolean enabled, int concurrentLogins, long rateInBytes,
                       int idleTimeInSeconds) {
        this.username = username;
        this.idleTimeInSeconds = idleTimeInSeconds;
        this.concurrentLogins = concurrentLogins;
        this.password = password;
        this.rateInBytes = rateInBytes;
        this.enabled = enabled;
        this.home = new File(home, username);
        DefaultUser.log.debug("the home directory should be " + this.home.getAbsolutePath());
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
        var rate = (int) this.rateInBytes;
        return List.of(new WritePermission(), new ConcurrentLoginPermission(this.concurrentLogins, this.concurrentLogins),
                new TransferRatePermission(rate, rate));
    }

    @Override
    public List<? extends Authority> getAuthorities(Class<? extends Authority> clazz) {
        var auths = getAuthorities().stream().filter(au -> au.getClass().isAssignableFrom(clazz)).toList();
        DefaultUser.log.info("have the following authentications for [" + auths +
                             "] : " + clazz.getName());
        return auths;
    }


    @Override
    public AuthorizationRequest authorize(AuthorizationRequest request) {
        if (request instanceof ConcurrentLoginRequest)
            return getAuthorities(ConcurrentLoginPermission.class).isEmpty() ? null : request;
        if (request instanceof TransferRateRequest)
            return getAuthorities(TransferRatePermission.class).isEmpty() ? null : request;
        if (request instanceof WriteRequest)
            return getAuthorities(WritePermission.class).isEmpty() ? null : request;
        return null;
    }

    @Override
    public int getMaxIdleTime() {
        return this.idleTimeInSeconds;
    }

    @Override
    public boolean getEnabled() {
        return this.enabled;
    }

    @Override
    public String getHomeDirectory() {
        return this.home.getAbsolutePath();
    }
}

class DefaultUserManager implements UserManager {

    private final Map<String, DefaultUser> users = new ConcurrentHashMap<>();

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