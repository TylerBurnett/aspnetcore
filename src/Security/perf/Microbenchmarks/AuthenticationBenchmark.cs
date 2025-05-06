// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using BenchmarkDotNet.Attributes;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.AspNetCore.Security;

public class AuthenticationBenchmark
{
    private static readonly SymmetricSecurityKey _validSigningKey = new(new byte[32]);
    private static readonly SymmetricSecurityKey _invalidSigningKey = new([.. Enumerable.Repeat((byte)1, 32)]);

    private static readonly string _validToken = CreateJwtToken(_validSigningKey);
    private static readonly string _invalidToken = CreateJwtToken(_invalidSigningKey);

    private IServiceProvider _serviceProvider;

    private IAuthenticationService _authenticationService;
    private HttpContext _httpContext;

    [GlobalSetup]
    public void GlobalSetup()
    {
        ServiceCollection serviceProvider = new ServiceCollection();
        serviceProvider.AddLogging();
        serviceProvider.AddOptions();
        serviceProvider.AddAuthentication()
            .AddJwtBearer(options =>
            {
                options.Audience = "audience";
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidIssuers = ["valid-issuer"],
                    ValidAudiences = ["valid-audience"],
                    IssuerSigningKey = _validSigningKey,
                };
            });

        _serviceProvider = serviceProvider.BuildServiceProvider(true);
    }

    [IterationSetup]
    public void Setup()
    {
        _authenticationService = _serviceProvider.CreateScope().ServiceProvider.GetRequiredService<IAuthenticationService>();
        _httpContext = new DefaultHttpContext
        {
            RequestServices = _serviceProvider,
        };
    }

    [Benchmark]
    public async Task AuthenticateAsync_ValidToken()
    {
        _httpContext.Request.Headers.Append("Authorization", $"Bearer {_validToken}");
        await _authenticationService.AuthenticateAsync(_httpContext, null);
    }

    [Benchmark]
    public async Task ChallengeAsync_ValidToken()
    {
        _httpContext.Request.Headers.Append("Authorization", $"Bearer {_validToken}");
        await _authenticationService.ChallengeAsync(_httpContext, null, null);
    }

    [Benchmark]
    public async Task AuthenticateAsync_InvalidToken()
    {
        _httpContext.Request.Headers.Append("Authorization", $"Bearer {_invalidToken}");
        await _authenticationService.AuthenticateAsync(_httpContext, null);
    }

    [Benchmark]
    public async Task ChallengeAsync_InvalidToken()
    {
        _httpContext.Request.Headers.Append("Authorization", $"Bearer {_invalidToken}");
        await _authenticationService.ChallengeAsync(_httpContext, null, null);
    }

    private static string CreateJwtToken(SymmetricSecurityKey signingKey)
    {
        var token = new JwtSecurityToken(
            issuer: "benchmark-issuer",
            audience: "benchmark-audience",
            claims:
            [
                new Claim(ClaimTypes.NameIdentifier, "BenchmarkUser"),
                new Claim(ClaimTypes.Email, "benchmark@example.com")
            ],
            expires: DateTime.Now.AddMinutes(30),
            signingCredentials: new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256));

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
