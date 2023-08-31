// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using Microsoft.IdentityModel.Logging;

using JsonPrimitives = Microsoft.IdentityModel.Tokens.Json.JsonSerializerPrimitives;
using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// A class which contains useful methods for processing tokens.
    /// </summary>
    internal class TokenUtilities
    {
        /// <summary>
        /// A URI that represents the JSON XML data type.
        /// </summary>
        /// <remarks>When mapping json to .Net Claim(s), if the value was not a string (or an enumeration of strings), the ClaimValue will serialized using the current JSON serializer, a property will be added with the .Net type and the ClaimTypeValue will be set to 'JsonClaimValueType'.</remarks>
        internal const string Json = "JSON";

        /// <summary>
        /// A URI that represents the JSON array XML data type.
        /// </summary>
        /// <remarks>When mapping json to .Net Claim(s), if the value was not a string (or an enumeration of strings), the ClaimValue will serialized using the current JSON serializer, a property will be added with the .Net type and the ClaimTypeValue will be set to 'JsonClaimValueType'.</remarks>
        internal const string JsonArray = "JSON_ARRAY";

        /// <summary>
        /// A URI that represents the JSON null data type
        /// </summary>
        /// <remarks>When mapping json to .Net Claim(s), we use empty string to represent the claim value and set the ClaimValueType to JsonNull</remarks>
        internal const string JsonNull = "JSON_NULL";

        /// <summary>
        /// Creates a dictionary from a list of Claim's.
        /// </summary>
        /// <param name="claims"> A list of claims.</param>
        /// <returns> A Dictionary representing claims.</returns>
        internal static Dictionary<string, object> CreateDictionaryFromClaims(IEnumerable<Claim> claims)
        {
            var payload = new Dictionary<string, object>();

            if (claims == null)
                return payload;

            foreach (Claim claim in claims)
            {
                if (claim == null)
                    continue;

                string jsonClaimType = claim.Type;
                object jsonClaimValue = claim.ValueType.Equals(ClaimValueTypes.String) ? claim.Value : GetClaimValueUsingValueType(claim);
                object existingValue;

                // If there is an existing value, append to it.
                // What to do if the 'ClaimValueType' is not the same.
                if (payload.TryGetValue(jsonClaimType, out existingValue))
                {
                    IList<object> claimValues = existingValue as IList<object>;
                    if (claimValues == null)
                    {
                        claimValues = new List<object>
                        {
                            existingValue
                        };

                        payload[jsonClaimType] = claimValues;
                    }

                    claimValues.Add(jsonClaimValue);
                }
                else
                {
                    payload[jsonClaimType] = jsonClaimValue;
                }
            }

            return payload;
        }

        internal static Dictionary<string, object> CreateDictionaryFromClaims(
            IEnumerable<Claim> claims,
            SecurityTokenDescriptor tokenDescriptor,
            bool audienceSet,
            bool issuerSet)
        {
            var payload = new Dictionary<string, object>();

            if (claims == null)
                return payload;

            bool checkClaims = tokenDescriptor.Claims != null && tokenDescriptor.Claims.Count > 0;

            foreach (Claim claim in claims)
            {
                if (claim == null)
                    continue;

                // skipping these as they will be added once by the caller
                // why add them if we are going to replace them later
                if (checkClaims && tokenDescriptor.Claims.ContainsKey(claim.Type))
                    continue;

                if (audienceSet && claim.Type.Equals("aud", StringComparison.Ordinal))
                    continue;

                if (issuerSet && claim.Type.Equals("iss", StringComparison.Ordinal))
                    continue;

                if (tokenDescriptor.Expires.HasValue && claim.Type.Equals("exp", StringComparison.Ordinal))
                    continue;

                if (tokenDescriptor.IssuedAt.HasValue && claim.Type.Equals("iat", StringComparison.Ordinal))
                    continue;

                if (tokenDescriptor.NotBefore.HasValue && claim.Type.Equals("nbf", StringComparison.Ordinal))
                    continue;

                object jsonClaimValue = claim.ValueType.Equals(ClaimValueTypes.String) ? claim.Value : GetClaimValueUsingValueType(claim);

                // The enumeration is from ClaimsIdentity.Claims, there can be duplicates.
                // When a duplicate is detected, we create a List and add both to a list.
                // When the creating the JWT and a list is found, a JsonArray will be created.
                if (payload.TryGetValue(claim.Type, out object existingValue))
                {
                    if (existingValue is List<object> existingList)
                    {
                        existingList.Add(jsonClaimValue);
                    }
                    else
                    {
                        payload[claim.Type] = new List<object>
                        {
                            existingValue,
                            jsonClaimValue
                        };
                    }
                }
                else
                {
                    payload[claim.Type] = jsonClaimValue;
                }
            }

            return payload;
        }

        internal static object GetClaimValueUsingValueType(Claim claim)
        {
            if (claim.ValueType == ClaimValueTypes.String)
                return claim.Value;

            if (claim.ValueType == ClaimValueTypes.Boolean && bool.TryParse(claim.Value, out bool boolValue))
                return boolValue;

            if (claim.ValueType == ClaimValueTypes.Double && double.TryParse(claim.Value, NumberStyles.Any, CultureInfo.InvariantCulture, out double doubleValue))
                return doubleValue;

            if ((claim.ValueType == ClaimValueTypes.Integer || claim.ValueType == ClaimValueTypes.Integer32) && int.TryParse(claim.Value, NumberStyles.Any, CultureInfo.InvariantCulture, out int intValue))
                return intValue;

            if (claim.ValueType == ClaimValueTypes.Integer64 && long.TryParse(claim.Value, out long longValue))
                return longValue;

            if (claim.ValueType == ClaimValueTypes.DateTime && DateTime.TryParse(claim.Value, out DateTime dateTimeValue))
                return dateTimeValue.ToUniversalTime();

            if (claim.ValueType == Json)
                return JsonPrimitives.CreateJsonElement(claim.Value);

            if (claim.ValueType == JsonArray)
                return JsonPrimitives.CreateJsonElement(claim.Value);

            if (claim.ValueType == JsonNull)
                return string.Empty;

            return claim.Value;
        }

        /// <summary>
        /// Returns all <see cref="SecurityKey"/> provided in <paramref name="configuration"/> and <paramref name="validationParameters"/>.
        /// </summary>
        /// <param name="configuration">The <see cref="BaseConfiguration"/> that contains signing keys used for validation.</param>
        /// <param name="validationParameters">A <see cref="TokenValidationParameters"/> required for validation.</param>
        /// <returns>Returns all <see cref="SecurityKey"/> provided in provided in <paramref name="configuration"/> and <paramref name="validationParameters"/>.</returns>
        internal static IEnumerable<SecurityKey> GetAllSigningKeys(BaseConfiguration configuration = null, TokenValidationParameters validationParameters = null)
        {
            if (configuration is not null)
            {
                if (validationParameters is not null)
                {
                    LogHelper.LogInformation(TokenLogMessages.IDX10264);
                }

                LogHelper.LogInformation(TokenLogMessages.IDX10265);

                if (configuration?.SigningKeys != null)
                    foreach (SecurityKey key in configuration.SigningKeys)
                        yield return key;
            }

            // TODO - do not use yield
            if (validationParameters is not null)
            {
                LogHelper.LogInformation(TokenLogMessages.IDX10243);

                if (validationParameters.IssuerSigningKey != null)
                    yield return validationParameters.IssuerSigningKey;

                if (validationParameters.IssuerSigningKeys != null)
                    foreach (SecurityKey key in validationParameters.IssuerSigningKeys)
                        yield return key;
            }
        }

        /// <summary>
        /// Returns the size in bytes for a signature algorithm
        /// </summary>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        internal static int GetSignatureSize(string algorithm)
        {
            switch (algorithm)
            {
                case SecurityAlgorithms.RsaSha256:
                case SecurityAlgorithms.EcdsaSha256:
                case SecurityAlgorithms.HmacSha256:
                case SecurityAlgorithms.RsaSha256Signature:
                case SecurityAlgorithms.RsaSsaPssSha256:
                case SecurityAlgorithms.EcdsaSha256Signature:
                case SecurityAlgorithms.HmacSha256Signature:
                case SecurityAlgorithms.RsaSsaPssSha256Signature:
                    return 512;

                case SecurityAlgorithms.RsaSha384:
                case SecurityAlgorithms.EcdsaSha384:
                case SecurityAlgorithms.HmacSha384:
                case SecurityAlgorithms.RsaSha384Signature:
                case SecurityAlgorithms.EcdsaSha384Signature:
                case SecurityAlgorithms.HmacSha384Signature:
                case SecurityAlgorithms.RsaSsaPssSha384:
                case SecurityAlgorithms.RsaSsaPssSha384Signature:
                    return 768;

                case SecurityAlgorithms.RsaSha512:
                case SecurityAlgorithms.EcdsaSha512:
                case SecurityAlgorithms.RsaSha512Signature:
                case SecurityAlgorithms.EcdsaSha512Signature:
                case SecurityAlgorithms.HmacSha512:
                case SecurityAlgorithms.HmacSha512Signature:
                case SecurityAlgorithms.RsaSsaPssSha512:
                case SecurityAlgorithms.RsaSsaPssSha512Signature:
                    return 1024;

                default: return -1;
            }
        }

        internal static bool AreBytesEqual(ReadOnlySpan<byte> bytes1, ReadOnlySpan<byte> bytes2)
        {
            if (bytes1.Length != bytes2.Length)
                return false;

            for (int i = 0; i < bytes1.Length; i++)
            {
                if (bytes1[i] != bytes2[i])
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Merges claims. If a claim with same type exists in both <paramref name="claims"/> and <paramref name="subjectClaims"/>, the one in claims will be kept.
        /// </summary>
        /// <param name="claims"> Collection of <see cref="Claim"/>'s.</param>
        /// <param name="subjectClaims"> Collection of <see cref="Claim"/>'s.</param>
        /// <returns> A Merged list of <see cref="Claim"/>'s.</returns>
        internal static IEnumerable<Claim> MergeClaims(IEnumerable<Claim> claims, IEnumerable<Claim> subjectClaims)
        {
            if (claims == null)
                return subjectClaims;

            if (subjectClaims == null)
                return claims;

            List<Claim> result = claims.ToList();

            foreach (Claim claim in subjectClaims)
            {
                if (!claims.Any(i => i.Type == claim.Type))
                    result.Add(claim);
            }

            return result;
        }

        /// <summary>
        /// Check whether the given exception type is recoverable by LKG.
        /// </summary>
        /// <param name="exception">The exception to check.</param>
        /// <returns><c>true</c> if the exception is certain types of exceptions otherwise, <c>false</c>.</returns>
        internal static bool IsRecoverableException(Exception exception)
        {
            return   exception is SecurityTokenInvalidSignatureException
                  || exception is SecurityTokenInvalidIssuerException
                  || exception is SecurityTokenSignatureKeyNotFoundException;
        }

        /// <summary>
        /// Check whether the given configuration is recoverable by LKG.
        /// </summary>
        /// <param name="kid">The kid from token."/></param>
        /// <param name="currentConfiguration">The <see cref="BaseConfiguration"/> to check.</param>
        /// <param name="lkgConfiguration">The LKG exception to check.</param>
        /// <param name="currentException">The exception to check.</param>
        /// <returns><c>true</c> if the configuration is recoverable otherwise, <c>false</c>.</returns>
        internal static bool IsRecoverableConfiguration(string kid, BaseConfiguration currentConfiguration, BaseConfiguration lkgConfiguration, Exception currentException)
        {
            Lazy<bool> isRecoverableSigningKey = new Lazy<bool>(() => lkgConfiguration.SigningKeys.Any(signingKey => signingKey.KeyId == kid));

            if (currentException is SecurityTokenInvalidIssuerException)
            {
                return currentConfiguration.Issuer != lkgConfiguration.Issuer;
            }
            else if (currentException is SecurityTokenSignatureKeyNotFoundException)
            {
                return isRecoverableSigningKey.Value;
            }
            else if (currentException is SecurityTokenInvalidSignatureException)
            {
                SecurityKey currentSigningKey = currentConfiguration.SigningKeys.FirstOrDefault(x => x.KeyId == kid);
                if (currentSigningKey == null)
                    return isRecoverableSigningKey.Value;

                SecurityKey lkgSigningKey = lkgConfiguration.SigningKeys.FirstOrDefault(signingKey => signingKey.KeyId == kid);
                return lkgSigningKey != null && currentSigningKey.InternalId != lkgSigningKey.InternalId;
            }

            return false;
        }
    }
}
