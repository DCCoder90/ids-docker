using System.Collections.Generic;
using IdentityServer4.Models;

namespace Ids
{
    public static class Config
    {
        public static IEnumerable<IdentityResource> StandardIdentityResources =>
          new IdentityResource[]
          {
              new IdentityResources.OpenId(),
              new IdentityResources.Profile(),
              new IdentityResources.Address(),
              new IdentityResources.Email()
          };
    }
}