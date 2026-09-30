package br.ufscar.dc.cloudlabs.keycloak;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

public class GitHubOrgAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "github-org-validator";
    private static final GitHubOrgAuthenticator SINGLETON = new GitHubOrgAuthenticator();

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "GitHub Organization Validator";
    }

    @Override
    public String getHelpText() {
        return "Valida se o usuário autenticado via GitHub pertence a uma ou mais organizações permitidas e opcionalmente exige cadastro de senha local.";
    }

    @Override
    public String getReferenceCategory() {
        return "github-validation";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        List<ProviderConfigProperty> properties = new ArrayList<>();

        // 1. Organizações permitidas (separadas por vírgula)
        ProviderConfigProperty orgsProperty = new ProviderConfigProperty();
        orgsProperty.setName(GitHubOrgAuthenticator.CONFIG_ALLOWED_ORGS);
        orgsProperty.setLabel("Organizações Permitidas");
        orgsProperty.setType(ProviderConfigProperty.STRING_TYPE);
        orgsProperty.setDefaultValue(GitHubOrgAuthenticator.DEFAULT_ORGS);
        orgsProperty.setHelpText("Lista de nomes das organizações no GitHub autorizadas, separadas por vírgula (ex: cloudlabs-ufscar, ufscar-lab). O usuário precisa pertencer a pelo menos uma delas.");
        properties.add(orgsProperty);

        // 2. Exigir senha local (UPDATE_PASSWORD)
        ProviderConfigProperty pwdProperty = new ProviderConfigProperty();
        pwdProperty.setName(GitHubOrgAuthenticator.CONFIG_REQUIRE_PASSWORD);
        pwdProperty.setLabel("Exigir Criação de Senha Local");
        pwdProperty.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        pwdProperty.setDefaultValue("true");
        pwdProperty.setHelpText("Se ativado, injeta a Required Action UPDATE_PASSWORD para que o usuário crie uma senha local antes de concluir o primeiro acesso.");
        properties.add(pwdProperty);

        // 3. Mensagem de erro customizada
        ProviderConfigProperty errorProperty = new ProviderConfigProperty();
        errorProperty.setName(GitHubOrgAuthenticator.CONFIG_CUSTOM_ERROR);
        errorProperty.setLabel("Mensagem de Erro Customizada (Opcional)");
        errorProperty.setType(ProviderConfigProperty.STRING_TYPE);
        errorProperty.setDefaultValue("");
        errorProperty.setHelpText("Mensagem exibida caso o usuário não pertença a nenhuma organização. Suporta os marcadores {user} e {orgs}. Se vazio, usa o texto padrão.");
        properties.add(errorProperty);

        return properties;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}
