using System;
using System.Collections.Generic;
using System.Linq;
using IdentityServer4.EntityFramework.DbContexts;
using IdentityServer4.EntityFramework.Entities;
using IdentityServer4.EntityFramework.Mappers;
using IdentityServer4.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using ApiResource = IdentityServer4.Models.ApiResource;
using ApiScope = IdentityServer4.Models.ApiScope;
using Client = IdentityServer4.Models.Client;
using ClientClaim = IdentityServer4.EntityFramework.Entities.ClientClaim;
using IdentityResource = IdentityServer4.Models.IdentityResource;

namespace Ids
{
    internal static class Initialize
    {
        public static void Clients(ILogger logger, ConfigurationDbContext configurationDbContext,
            IConfiguration configuration)
        {
            logger.LogInformation("Checking Clients for Updates");
            if (configuration.GetSection("Clients").Get<IEnumerable<Client>>() == null) return;
            foreach (var clientResource in configuration.GetSection("Clients").Get<IEnumerable<Client>>()
                .Where(x => !string.IsNullOrEmpty(x.ClientId)))
            {
                var entity =
                    configurationDbContext.Clients
                        .Include(x=>x.AllowedGrantTypes)
                        .Include(x=>x.ClientSecrets)
                        .Include(x=>x.PostLogoutRedirectUris)
                        .Include(x=>x.RedirectUris)
                        .Include(x=>x.AllowedScopes)
                        .Include(x=>x.Properties)
                        .Include(x=>x.Claims)
                        .Include(x=>x.IdentityProviderRestrictions)
                        .Include(x=>x.AllowedCorsOrigins)
                        .SingleOrDefault(x => x.ClientId == clientResource.ClientId);
        
                if (entity == null)
                {
                    logger.LogInformation($"Creating Client {clientResource.ClientId}");

                    clientResource.ClientSecrets = clientResource.ClientSecrets.Select(x =>
                    {
                        x.Value = x.Value.Sha256();
                        return x;
                    }).ToList();
                    configurationDbContext.Clients.Add(clientResource.ToEntity());
                    configurationDbContext.SaveChanges();
                }
                else
                {
                    if (entity.Equals(clientResource.ToEntity()))
                        continue;
                    logger.LogInformation($"Updating Client {entity.ClientId}");
                   
                    var grantTypes = clientResource.AllowedGrantTypes.Select(x => new ClientGrantType
                    {
                        Client = entity,
                        ClientId = entity.Id,
                        GrantType = x
                    }).Where(x=>entity.AllowedGrantTypes.All(c=>c.GrantType != x.GrantType)).ToList();

                    if (grantTypes.Any())
                    {
                        entity.AllowedGrantTypes.RemoveAll(c=>!string.IsNullOrEmpty(c.GrantType));
                        entity.AllowedGrantTypes = grantTypes;
                    }
                    
                    var redirectUris = clientResource.RedirectUris.Select(x => new ClientRedirectUri
                    {
                        Client = entity,
                        ClientId = entity.Id,
                        RedirectUri = x
                    }).Where(x=>entity.RedirectUris.All(c=>c.RedirectUri != x.RedirectUri)).ToList();

                    if (redirectUris.Any())
                    {
                        entity.RedirectUris.RemoveAll(c => !string.IsNullOrEmpty(c.RedirectUri));
                        entity.RedirectUris = redirectUris;
                    }

                    var postLogoutUris = clientResource.PostLogoutRedirectUris.Select(x =>
                        new ClientPostLogoutRedirectUri
                        {
                            ClientId = entity.Id,
                            Client = entity,
                            PostLogoutRedirectUri = x
                        })
                        .Where(x=>
                            entity.PostLogoutRedirectUris.All(c=>c.PostLogoutRedirectUri != x.PostLogoutRedirectUri))
                        .ToList();

                    if (postLogoutUris.Any())
                    {
                        entity.PostLogoutRedirectUris.RemoveAll(c => !string.IsNullOrEmpty(c.PostLogoutRedirectUri));
                        entity.PostLogoutRedirectUris = postLogoutUris;
                    }

                    var allowedScopes = clientResource.AllowedScopes.Select(x => new ClientScope
                    {
                        ClientId = entity.Id,
                        Client = entity,
                        Scope = x
                    }).Where(x=>
                            entity.AllowedScopes.All(c=>c.Scope != x.Scope))
                        .ToList();

                    if (allowedScopes.Any())
                    {
                        entity.AllowedScopes.RemoveAll(c => !string.IsNullOrEmpty(c.Scope));
                        entity.AllowedScopes = allowedScopes;
                    }
                    
                    var idPRestrictions = clientResource.IdentityProviderRestrictions.Select(x =>
                        new ClientIdPRestriction
                        {
                            ClientId = entity.Id,
                            Client = entity,
                            Provider = x
                        }).Where(x=>
                            entity.IdentityProviderRestrictions.All(c=>c.Provider != x.Provider))
                        .ToList();
                    
                    if (idPRestrictions.Any())
                    {
                        entity.IdentityProviderRestrictions.RemoveAll(c => !string.IsNullOrEmpty(c.Provider));
                        entity.IdentityProviderRestrictions = idPRestrictions;
                    }
                    
                    var claims = clientResource.Claims.Select(x=>new ClientClaim
                    {
                        ClientId = entity.Id,
                        Client = entity,
                        Type = x.Type,
                        Value = x.Value
                    }).Where(x=>
                            entity.Claims.All(c=>c.Value != x.Value && c.Type != x.Type))
                        .ToList();
                    
                    if (claims.Any())
                    {
                        entity.Claims.RemoveAll(c => !string.IsNullOrEmpty(c.Type));
                        entity.Claims = claims;
                    }
                    
                    var allowedCorsOrigins = clientResource.AllowedCorsOrigins.Select(x=>new ClientCorsOrigin
                    {
                        ClientId = entity.Id,
                        Client = entity,
                        Origin = x
                    }).Where(x=>
                            entity.AllowedCorsOrigins.All(c=>c.Origin != x.Origin))
                        .ToList();
                    
                    if (allowedCorsOrigins.Any())
                    {
                        entity.AllowedCorsOrigins.RemoveAll(c => !string.IsNullOrEmpty(c.Origin));
                        entity.AllowedCorsOrigins = allowedCorsOrigins;
                    }
                    
                    var clientProperties = clientResource.Properties.Select(x=>new ClientProperty
                    {
                        ClientId = entity.Id,
                        Client = entity,
                        Key = x.Key,
                        Value = x.Value
                    }).Where(x=>
                            entity.Properties.All(c=>c.Key != x.Key && c.Value != x.Value))
                        .ToList();
                    
                    if (clientProperties.Any())
                    {
                        entity.Properties.RemoveAll(c => !string.IsNullOrEmpty(c.Key));
                        entity.Properties = clientProperties;
                    }
                    
                    entity.Enabled = clientResource.Enabled;
                    entity.ProtocolType = clientResource.ProtocolType;
                    entity.RequireClientSecret = clientResource.RequireClientSecret;
                    entity.ClientName = clientResource.ClientName;
                    entity.Description = clientResource.Description;
                    entity.ClientUri = clientResource.ClientUri;
                    entity.LogoUri = clientResource.LogoUri;
                    entity.RequireConsent = clientResource.RequireConsent;
                    entity.AllowRememberConsent = clientResource.AllowRememberConsent;
                    entity.RequirePkce = clientResource.RequirePkce;
                    entity.AllowPlainTextPkce = clientResource.AllowPlainTextPkce;
                    entity.RequireRequestObject = clientResource.RequireRequestObject;
                    entity.AllowAccessTokensViaBrowser = clientResource.AllowAccessTokensViaBrowser;
                    entity.FrontChannelLogoutUri = clientResource.FrontChannelLogoutUri;
                    entity.FrontChannelLogoutSessionRequired = clientResource.FrontChannelLogoutSessionRequired;
                    entity.BackChannelLogoutUri = clientResource.BackChannelLogoutUri;
                    entity.BackChannelLogoutSessionRequired = clientResource.BackChannelLogoutSessionRequired;
                    entity.AllowOfflineAccess = clientResource.AllowOfflineAccess;
                    entity.AlwaysIncludeUserClaimsInIdToken = clientResource.AlwaysIncludeUserClaimsInIdToken;
                    entity.IdentityTokenLifetime = clientResource.IdentityTokenLifetime;
                    entity.AllowedIdentityTokenSigningAlgorithms = string.Join(',', clientResource.AllowedIdentityTokenSigningAlgorithms);
                    entity.AccessTokenLifetime = clientResource.AccessTokenLifetime;
                    entity.AuthorizationCodeLifetime = clientResource.AuthorizationCodeLifetime;
                    entity.AbsoluteRefreshTokenLifetime = clientResource.AbsoluteRefreshTokenLifetime;
                    entity.SlidingRefreshTokenLifetime = clientResource.SlidingRefreshTokenLifetime;
                    entity.ConsentLifetime = clientResource.ConsentLifetime;
                    entity.RefreshTokenUsage = (int)clientResource.RefreshTokenUsage;
                    entity.UpdateAccessTokenClaimsOnRefresh = clientResource.UpdateAccessTokenClaimsOnRefresh;
                    entity.RefreshTokenExpiration = (int)clientResource.RefreshTokenExpiration;
                    entity.AccessTokenType = (int) clientResource.AccessTokenType;
                    entity.EnableLocalLogin = clientResource.EnableLocalLogin;
                    entity.IncludeJwtId = clientResource.IncludeJwtId;
                    entity.AlwaysSendClientClaims = clientResource.AlwaysSendClientClaims;
                    entity.ClientClaimsPrefix = clientResource.ClientClaimsPrefix;
                    entity.PairWiseSubjectSalt = clientResource.PairWiseSubjectSalt;
                    entity.UserSsoLifetime = clientResource.UserSsoLifetime;
                    entity.UserCodeType = clientResource.UserCodeType;
                    entity.DeviceCodeLifetime = clientResource.DeviceCodeLifetime;


                    foreach (var secret in clientResource.ClientSecrets)
                    {
                        if (entity.ClientSecrets.Any(x =>
                            x.Value == secret.Value.Sha256() &&
                            x.Expiration == secret.Expiration &&
                            x.Type == secret.Type))
                            continue;

                        entity.ClientSecrets.Add(new ClientSecret
                        {
                            ClientId = entity.Id,
                            Client = entity, 
                            Description = secret.Description, 
                            Expiration = secret.Expiration, 
                            Type = secret.Type,
                            Value = secret.Value.Sha256()
                        });
                    }
                    entity.Updated = DateTime.Now;

                    configurationDbContext.SaveChanges();
                }
            }
        }

        public static void IdentityResources(ILogger logger, ConfigurationDbContext configurationDbContext,
            IConfiguration configuration)
        {
            logger.LogInformation("Checking Identity Resources for Updates");

            var identityResources = Config.StandardIdentityResources.ToList();
            var fromConfig = configuration.GetSection("IdentityResources").Get<IEnumerable<IdentityResource>>();
            identityResources.AddRange(fromConfig);
            foreach (var resource in identityResources.Where(resource => !string.IsNullOrEmpty(resource.Name)))
            {
                var entity =
                    configurationDbContext.IdentityResources.SingleOrDefault(
                        x => x.Name == resource.Name);
                
                if (entity != null)
                {
                    if (entity.Equals(resource.ToEntity()))
                        continue;
                    logger.LogInformation($"Updating {resource.Name}");
                    entity.DisplayName = resource.DisplayName;
                    entity.Emphasize = resource.Emphasize;
                    entity.Required = resource.Required;
                    entity.Description = resource.Description;
                    configurationDbContext.SaveChanges();
                }
                else
                {
                    logger.LogInformation($"Creating {resource.Name}");
                    configurationDbContext.IdentityResources.Add(resource.ToEntity());
                    configurationDbContext.SaveChanges();
                }
            }
        }

        public static void ApiResources(ILogger logger, ConfigurationDbContext configurationDbContext,
            IConfiguration configuration)
        {
            logger.LogInformation("Checking API Resources for Updates");

            foreach (var apiResource in configuration.GetSection("ApiResources").Get<IEnumerable<ApiResource>>())      
            {
                if (string.IsNullOrEmpty(apiResource.Name))
                    continue;
                var entity =
                    configurationDbContext.ApiResources.SingleOrDefault(
                        x => x.Name == apiResource.Name);
                
                if (entity != null)
                {
                    if (entity.Equals(apiResource.ToEntity()))
                        continue;
                    logger.LogInformation($"Updating {apiResource.Name}");
                    entity.DisplayName = apiResource.DisplayName;
                    entity.Description = apiResource.Description;
                    configurationDbContext.SaveChanges();
                }
                else
                {
                    logger.LogInformation($"Creating {apiResource.Name}");
                    configurationDbContext.ApiResources.Add(apiResource.ToEntity());
                    configurationDbContext.SaveChanges();
                }
            }
        }
        
        public static void ApiScopes(ILogger logger, ConfigurationDbContext configurationDbContext, IConfiguration configuration)
        {
            logger.LogInformation("Checking API Scopes for Updates");

            foreach (var apiScope in configuration.GetSection("ApiScopes").Get<IEnumerable<ApiScope>>())
            {
                if (string.IsNullOrEmpty(apiScope.Name))
                    continue;
                var entity =
                    configurationDbContext.ApiScopes.SingleOrDefault(
                        x => x.Name == apiScope.Name);
                
                if (entity != null)
                {
                    if (entity.Equals(apiScope.ToEntity()))
                        continue;
                    logger.LogInformation($"Updating {apiScope.Name}");
                    entity.DisplayName = apiScope.DisplayName;
                    entity.Description = apiScope.Description;
                    configurationDbContext.SaveChanges();
                }
                else
                {
                    logger.LogInformation($"Creating {apiScope.Name}");
                    configurationDbContext.ApiScopes.Add(apiScope.ToEntity());
                    configurationDbContext.SaveChanges();
                }
            }
        }
    }
}