# @vatsdev/encryption-decryption-poc

A TypeScript library for secure encryption and decryption using Google Cloud KMS and Secret Manager.

## Features

- Secure encryption and decryption using Google Cloud KMS
- Secret management with Google Cloud Secret Manager
- TypeScript support with full type definitions
- Easy integration with Sequelize models
- Support for field-level encryption
- Automatic key management and rotation

## Installation

```bash
npm install @vatsdev/encryption-decryption-poc
```

## Prerequisites

- Node.js >= 14.0.0
- Google Cloud Platform account with KMS and Secret Manager enabled
- Proper GCP credentials configured

## Usage

```typescript
import { EncryptionService, KMSService, SecretManagerService } from '@vatsdev/encryption-decryption-poc';

// Initialize services
const kmsService = new KMSService();
const secretManagerService = new SecretManagerService();
const encryptionService = new EncryptionService();

// Encrypt data
const encryptedData = await encryptionService.encryptObject({
  data: { sensitiveField: 'value' },
  model: YourModel,
  metadata: {
    locationId: 'global',
    keyRingId: 'your-key-ring',
    keyId: 'your-key'
  }
});

// Decrypt data
const decryptedData = await encryptionService.decryptObject({
  data: encryptedData.data,
  model: YourModel,
  metadata: encryptedData.metadata
});
```

## Configuration

The library requires the following environment variables:

- `GOOGLE_CLOUD_PROJECT`: Your Google Cloud project ID
- `KMS_LOCATION_ID`: Location ID for KMS (defaults to 'global')

## API Documentation

### EncryptionService

The main service for handling encryption and decryption operations.

#### Methods

- `encryptObject`: Encrypts an object using the specified model's configuration
- `decryptObject`: Decrypts an object using the provided metadata

### KMSService

Service for managing encryption keys in Google Cloud KMS.

#### Methods

- `encryptDEK`: Encrypts a Data Encryption Key (DEK)
- `decryptDEK`: Decrypts a Data Encryption Key (DEK)

### SecretManagerService

Service for managing secrets in Google Cloud Secret Manager.

#### Methods

- `createSecret`: Creates a new secret and adds the encrypted DEK as a version
- `getSecret`: Retrieves the latest version of a secret

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT 