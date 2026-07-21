using System.Security.Cryptography;

using var rsa = RSA.Create(4096);

// Write public key PEM to stdout
Console.WriteLine(rsa.ExportSubjectPublicKeyInfoPem());

// Write private key to file in project root
var projectRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));
var privateKeyPath = Path.Combine(projectRoot, "update-signing-key.pem");
File.WriteAllText(privateKeyPath, rsa.ExportRSAPrivateKeyPem());
Console.Error.WriteLine($"Private key written to: {privateKeyPath}");
