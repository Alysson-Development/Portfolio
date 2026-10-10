
using Azure.Identity;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;

namespace Portfolio.Services;

public sealed class AzureBlobStorageService : IStorageService
{
    private readonly BlobContainerClient _container;

    public AzureBlobStorageService(IConfiguration configuration)
    {
        var serviceUri = configuration["Blob:ServiceUri"]
            ?? throw new InvalidOperationException(
                "Blob:ServiceUri não configurado.");

        var containerName = configuration["Blob:Container"]
            ?? throw new InvalidOperationException(
                "Blob:Container não configurado.");

        var serviceClient = new BlobServiceClient(
            new Uri(serviceUri),
            new DefaultAzureCredential());

        _container = serviceClient.GetBlobContainerClient(containerName);
    }

    public async Task<string> UploadAsync(
        Stream content,
        string fileName,
        string contentType,
        string kind,
        CancellationToken cancellationToken = default)
    {
        var allowedKinds = new HashSet<string>(
            StringComparer.OrdinalIgnoreCase)
        {
            "projects",
            "education",
            "profile",
            "technologies",
            "cv"
        };

        if (!allowedKinds.Contains(kind))
            throw new ArgumentException("Tipo de arquivo inválido.", nameof(kind));

        var extension = Path.GetExtension(fileName).ToLowerInvariant();
        var objectName = $"{kind}/{Guid.NewGuid():N}{extension}";
        var blob = _container.GetBlobClient(objectName);

        await blob.UploadAsync(
            content,
            new BlobUploadOptions
            {
                HttpHeaders = new BlobHttpHeaders
                {
                    ContentType = contentType
                }
            },
            cancellationToken);

        return blob.Uri.ToString();
    }

    public async Task DeleteAsync(
        string? url,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(url))
            return;

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return;

        var containerUri = _container.Uri;

        if (!string.Equals(uri.Host, containerUri.Host,
                StringComparison.OrdinalIgnoreCase))
            return;

        var prefix = containerUri.AbsolutePath.TrimEnd('/') + "/";

        if (!uri.AbsolutePath.StartsWith(
                prefix, StringComparison.Ordinal))
            return;

        var objectName = Uri.UnescapeDataString(
            uri.AbsolutePath[prefix.Length..]);

        if (string.IsNullOrWhiteSpace(objectName))
            return;

        await _container
            .GetBlobClient(objectName)
            .DeleteIfExistsAsync(
                cancellationToken: cancellationToken);
    }
}
