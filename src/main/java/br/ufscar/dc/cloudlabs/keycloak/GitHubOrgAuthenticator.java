package br.ufscar.dc.cloudlabs.keycloak;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;

import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Keycloak Authenticator SPI de Propósito Geral:
 * - Valida se o usuário autenticado via GitHub pertence a uma ou mais organizações permitidas.
 * - Suporta lista de organizações separadas por vírgula.
 * - Permite configurar se o usuário deve ser forçado a cadastrar uma senha local (UPDATE_PASSWORD).
 * - Mensagens e regras customizáveis via console de administração do Keycloak.
 */
public class GitHubOrgAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(GitHubOrgAuthenticator.class);
    private static final ObjectMapper mapper = new ObjectMapper();

    public static final String CONFIG_ALLOWED_ORGS = "allowed_organizations";
    public static final String CONFIG_REQUIRE_PASSWORD = "require_local_password";
    public static final String CONFIG_CUSTOM_ERROR = "custom_error_message";

    public static final String DEFAULT_ORGS = "cloudlabs-ufscar";
    public static final boolean DEFAULT_REQUIRE_PASSWORD = true;

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        logger.info("================================================================================");
        logger.info("[GitHub-Org-Validator] Disparado no First Broker Login.");

        BrokeredIdentityContext brokerContext = (BrokeredIdentityContext) context.getAuthenticationSession()
                .getAuthNote(KeycloakModelUtils.BROKERED_IDENTITY_CONTEXT);

        if (brokerContext == null) {
            logger.warn("[GitHub-Org-Validator] BrokeredIdentityContext ausente na sessão. Ignorando validação.");
            logger.info("================================================================================");
            context.success();
            return;
        }

        String providerId = brokerContext.getIdpConfig().getProviderId();
        if (!"github".equalsIgnoreCase(providerId)) {
            logger.infof("[GitHub-Org-Validator] Provedor '%s' não é GitHub. Validador ignorado.", providerId);
            logger.info("================================================================================");
            context.success();
            return;
        }

        String githubUsername = brokerContext.getUsername();
        String accessToken = brokerContext.getToken();

        // 1. Carrega configurações do Authenticator
        AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
        String allowedOrgsRaw = DEFAULT_ORGS;
        boolean requirePassword = DEFAULT_REQUIRE_PASSWORD;
        String customErrorMessage = null;

        if (configModel != null && configModel.getConfig() != null) {
            allowedOrgsRaw = configModel.getConfig().getOrDefault(CONFIG_ALLOWED_ORGS, DEFAULT_ORGS);
            requirePassword = Boolean.parseBoolean(configModel.getConfig().getOrDefault(CONFIG_REQUIRE_PASSWORD, "true"));
            customErrorMessage = configModel.getConfig().get(CONFIG_CUSTOM_ERROR);
        }

        Set<String> allowedOrgs = Arrays.stream(allowedOrgsRaw.split(","))
                .map(String::trim)
                .map(String::toLowerCase)
                .filter(s -> !s.isBlank())
                .collect(Collectors.toSet());

        logger.infof("[GitHub-Org-Validator] Usuário autenticado: @%s", githubUsername);
        logger.infof("[GitHub-Org-Validator] Organizações autorizadas configuradas: %s", allowedOrgs);
        logger.infof("[GitHub-Org-Validator] Exigir senha local (UPDATE_PASSWORD): %b", requirePassword);

        if (accessToken == null || accessToken.isBlank()) {
            logger.errorf("[GitHub-Org-Validator] ERRO: Token OAuth do GitHub ausente para @%s. Verifique o escopo 'read:org' no IdP.", githubUsername);
            logger.info("================================================================================");
            Response errorResponse = context.form()
                    .setError("Não foi possível obter o token de autorização do GitHub.")
                    .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR);
            context.failure(AuthenticationFlowError.INTERNAL_ERROR, errorResponse);
            return;
        }

        // 2. Valida membership
        boolean isAuthorized = checkUserOrganizations(context.getSession(), githubUsername, accessToken, allowedOrgs);

        if (!isAuthorized) {
            logger.warnf("[GitHub-Org-Validator] ❌ ACESSO NEGADO: Usuário @%s NÃO pertence a nenhuma das organizações: %s", githubUsername, allowedOrgs);
            logger.info("================================================================================");
            
            String errorMsg = (customErrorMessage != null && !customErrorMessage.isBlank())
                    ? customErrorMessage.replace("{user}", githubUsername).replace("{orgs}", allowedOrgsRaw)
                    : "Acesso restrito: Sua conta do GitHub (@" + githubUsername + ") não pertence a nenhuma das organizações autorizadas (" + allowedOrgsRaw + ").";

            Response errorResponse = context.form()
                    .setError(errorMsg)
                    .createErrorPage(Response.Status.FORBIDDEN);
            context.failure(AuthenticationFlowError.ACCESS_DENIED, errorResponse);
            return;
        }

        logger.infof("[GitHub-Org-Validator] ✅ ACESSO APROVADO: Usuário @%s é membro autorizado!", githubUsername);

        // 3. Força senha local se configurado
        if (requirePassword) {
            logger.infof("[GitHub-Org-Validator] 🔑 Injetando Required Action 'UPDATE_PASSWORD' para @%s.", githubUsername);
            context.getAuthenticationSession().addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
        }

        logger.info("================================================================================");
        context.success();
    }

    /**
     * Consulta as organizações do usuário via API do GitHub (/user/orgs e fallback para /orgs/{org}/members/{user})
     */
    private boolean checkUserOrganizations(KeycloakSession session, String username, String token, Set<String> allowedOrgs) {
        CloseableHttpClient httpClient = session.getProvider(HttpClientProvider.class).getHttpClient();
        List<String> foundOrgs = new ArrayList<>();

        // Estratégia 1: Busca todas as organizações do usuário em 1 chamada rápida (/user/orgs)
        try {
            logger.info("[GitHub-Org-Validator] Consultando endpoint https://api.github.com/user/orgs ...");
            HttpGet request = new HttpGet("https://api.github.com/user/orgs");
            request.setHeader("Authorization", "Bearer " + token);
            request.setHeader("Accept", "application/vnd.github+json");
            request.setHeader("User-Agent", "Keycloak-GitHub-Org-Authenticator");

            HttpResponse response = httpClient.execute(request);
            int statusCode = response.getStatusLine().getStatusCode();
            logger.infof("[GitHub-Org-Validator] Status da resposta de /user/orgs: %d", statusCode);

            if (statusCode == 200) {
                String json = EntityUtils.toString(response.getEntity());
                JsonNode orgsArray = mapper.readTree(json);
                if (orgsArray.isArray()) {
                    for (JsonNode orgNode : orgsArray) {
                        String orgLogin = orgNode.path("login").asText("").toLowerCase();
                        foundOrgs.add(orgLogin);
                        if (allowedOrgs.contains(orgLogin)) {
                            logger.infof("[GitHub-Org-Validator] Match confirmado! Usuário @%s pertence à organização autorizada: '%s'", username, orgLogin);
                            return true;
                        }
                    }
                }
                logger.infof("[GitHub-Org-Validator] Organizações públicas/visíveis do usuário encontradas: %s", foundOrgs);
            }
        } catch (Exception e) {
            logger.warnf(e, "[GitHub-Org-Validator] Falha ao consultar /user/orgs para @%s. Tentando endpoint individual...", username);
        }

        // Estratégia 2 (Fallback): Checa individualmente /orgs/{org}/members/{username}
        for (String org : allowedOrgs) {
            try {
                String url = String.format("https://api.github.com/orgs/%s/members/%s", org, username);
                logger.infof("[GitHub-Org-Validator] Consultando endpoint direto: %s", url);
                HttpGet request = new HttpGet(url);
                request.setHeader("Authorization", "Bearer " + token);
                request.setHeader("Accept", "application/vnd.github+json");
                request.setHeader("User-Agent", "Keycloak-GitHub-Org-Authenticator");

                HttpResponse response = httpClient.execute(request);
                int statusCode = response.getStatusLine().getStatusCode();
                logger.infof("[GitHub-Org-Validator] Resposta de %s: HTTP %d", url, statusCode);

                if (statusCode == 204 || statusCode == 200) {
                    logger.infof("[GitHub-Org-Validator] Match confirmado via consulta direta à org '%s'!", org);
                    return true;
                }
            } catch (IOException e) {
                logger.warnf("[GitHub-Org-Validator] Falha na consulta direta à organização '%s' para @%s: %s", org, username, e.getMessage());
            }
        }

        return false;
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        context.success();
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
}
