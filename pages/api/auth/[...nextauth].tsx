import { randomUUID, randomBytes } from "crypto";
import NextAuth from "next-auth";
import AzureADB2CProvider from "next-auth/providers/azure-ad-b2c";
import { type TokenSet } from "next-auth/core/types"
import { JWT } from "next-auth/jwt/types";

const tenantName = process.env.AUTH_TENANT_NAME;
const userFlow = process.env.USER_FLOW;
const clientID = process.env.AUTH_CLIENT_ID;
const secret = process.env.AUTH_CLIENT_SECRET;
const tenantId = "4bd58e7b-5da2-4c1c-ad57-0a10c56d4756";
  
//Reference to this module as below
//https://next-auth.js.org/v3/tutorials/refresh-token-rotation
    async function refreshAccessToken(token: JWT) {
      try {
        const tokenUrl = ` https://choueiri.b2clogin.com/choueiri.onmicrosoft.com/B2C_1_PA_SignIn/oauth2/v2.0/token?`;
    
        let formData = {
          client_id: process.env.AUTH_CLIENT_ID!,
          grant_type: "refresh_token",
          client_secret: secret,
          response_type:"token",
          scope: `offline_access openid https://${process.env.AUTH_TENANT_NAME}.onmicrosoft.com/parking/api/Request.Read`,
          nonce:12345,
          refresh_token: token.refresh_token,
        };

        const encodeFormData = (data: any) => {
          return Object.keys(data)
            .map((key) => encodeURIComponent(key) + "=" + encodeURIComponent(data[key]))
            .join("&");
        };

        const response = await fetch(tokenUrl, {
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
          method: "POST",
          body: encodeFormData(formData),
        });

        const refreshedTokens = await response.json();    
        if (!response.ok) {
          throw refreshedTokens;
        }
      token.access_token=refreshedTokens.access_token;
      token.expires_on=refreshedTokens.expires_on;
      token.refresh_token=refreshedTokens.refresh_token ?? token.refresh_token;
        return {
          ...token  
        };
      } catch (error) {
        console.log(error);
        return {
          ...token,
          error: "RefreshAccessTokenError",
        };
      }
    }

 export  const handler = NextAuth( {
  session: {
    strategy: "jwt",
  },
  debug: process.env.NODE_ENV !== "production",
  secret: process.env.NEXTAUTH_SECRET,
  providers: [
    AzureADB2CProvider({
      tenantId: tenantName,
      clientId: process.env.AUTH_CLIENT_ID!,
      clientSecret: process.env.AUTH_CLIENT_SECRET!,
      primaryUserFlow: process.env.USER_FLOW,
      authorization: { params: { scope: `offline_access openid https://${process.env.AUTH_TENANT_NAME}.onmicrosoft.com/parking/api/Request.Read` } },
      //authorization: { params: { scope: `https://${process.env.AUTH_TENANT_NAME}.onmicrosoft.com/parking/api/Request.Read offline_access openid` } },

      // authorization: { params: { scope: "offline_access openid",code_challenge_method:"S256",code_challenge:"71TNl4_ek-ZRSe1_G_PgF9LetPd6DCnUDv2NOM3dmp8" } },
      // checks: [ 'nonce','pkce','state' ],
    }),
    //code_challenge and code_challenge_method are not able to use with Next-Auth AzureADB2CProvider
    //if "Try signing in with a different account." error then use the http://localhost:3000/api/auth/signout/azure-ad-b2c and sign out
  ],
  callbacks: {
    // async signIn( {user, account, profile, email, credentials}:any ) {
    //   return true;
    // },
    // async redirect({ url, baseUrl }:any) {
    //   return url.startsWith(baseUrl) ? url : baseUrl;
    // },
    ////this module is to use to customise the return object of getToken()
    async jwt({ token, user, account, profile}: any) {
      
      if (user || account) {
          //add custom object
          token.access_token = account.access_token;         
          token.refresh_token = account.refresh_token;         
          token.role= profile.extension_Role;
          token.expires_on= account.expires_on; //Date.now() + account.expires_in * 1000  
          console.log(token.access_token);               
         return Promise.resolve(token);  
      }
      else{
        if (Date.now() < token.expires_on * 1000)
        {          
          return  Promise.resolve(token);
        }
        else{
        const t=await refreshAccessToken(token);
        token={...token,...t};  
        console.log(token.access_token);         
        return  Promise.resolve(token);
        }
      }
      ////this module is to use to customise the useSession object
      // async session({session, token}:any) {
      //   if (token) {
      //     session.user = {
      //       ...session.user,
      //       role: token.role,
      //       access_token: token.access_token,
      //     };
      //   } else {
      //     session.user = undefined;
      //   }
      //   return Promise.resolve(session);
      // },
  },
  async session({session, token}:any) {
        if (token) {
          session.user = {
            ...session.user,
            role: token.role,
            access_token: token.access_token,
          };
        } else {
          session.user = undefined;
        }
        return Promise.resolve(session);
      },
}
});
//const handler = NextAuth(options);
export { handler as GET, handler as POST };
