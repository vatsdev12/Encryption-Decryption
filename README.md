# Field-Level Encryption Service

A TypeScript-based service that provides field-level encryption capabilities using Google Cloud KMS and Secret Manager.

## Features

- Field-level encryption for sensitive data
- Integration with Google Cloud KMS for key management
- Secure storage of encrypted data encryption keys (DEKs) in Google Cloud Secret Manager
- Support for multiple encryption algorithms (AES-256-GCM, AES-256-CBC)
- Automatic key rotation and versioning
- Comprehensive error handling and validation

## Prerequisites

- Node.js (v14 or higher)
- TypeScript
- Google Cloud Platform account with:
  - Cloud KMS enabled
  - Secret Manager enabled
  - Appropriate IAM permissions
- Environment variables:
  - `GOOGLE_CLOUD_PROJECT`: Your GCP project ID
  - `GOOGLE_APPLICATION_CREDENTIALS`: Path to your service account key file

## Project Structure

```
src/
├── services/          # Core service implementations
├── utils/            # Utility functions and helpers
├── types/            # TypeScript type definitions
├── index.ts          # Main entry point
├── functions.ts      # Function exports
└── types.ts          # Type exports
```

## Core Components

### Main Entry Point (`index.ts`)
- Exports main functionality
- Provides service initialization
- Handles configuration setup

### Services Directory
Contains core service implementations for:
- Encryption/Decryption operations
- KMS integration
- Secret Manager integration

### Utils Directory
Contains utility functions for:
- Encryption/Decryption helpers
- Data validation
- Error handling

### Types Directory
Contains TypeScript type definitions for:
- Service interfaces
- Configuration types
- Error types

## Error Handling

The service implements a comprehensive error handling system with custom error types:

- `ConfigurationError`: For initialization and configuration issues
- `EncryptionError`: For encryption/decryption failures
- `ValidationError`: For input validation failures

Each error type includes specific error codes for better error tracking and handling.

## Configuration

### Environment Variables

The package uses the following environment variables:

- `ENCRYPTION_CONFIG_PATH`: Path to your encryption configuration file (optional)
- `GOOGLE_CLOUD_PROJECT`: Your GCP project ID (required)
- `GOOGLE_APPLICATION_CREDENTIALS`: Path to your service account key file (required)

### Configuration File

The encryption configuration file (`encryption.json`) can be placed in one of these locations:
1. Path specified by `ENCRYPTION_CONFIG_PATH` environment variable
2. `./config/encryption.json`
3. `./src/config/encryption.json`
4. `./encryption.json`

Example configuration file:
```json
{
  "encryptedFields": {
    "User": {
      "Encrypt": [
        {
          "key": "email",
          "shouldHash": true
        },
        {
          "key": "phone",
          "shouldHash": false
        }
      ],
      "Decrypt": [
        {
          "key": "email"
        },
        {
          "key": "phone"
        }
      ]
    }
  }
}
```

### Using in Your Project

1. Install the package:
   ```bash
   npm install @vatsdev/encryption-decryption-poc
   ```

2. Set up environment variables in your project:
   ```bash
   # .env file
   ENCRYPTION_CONFIG_PATH=/path/to/your/encryption.json
   GOOGLE_CLOUD_PROJECT=your-project-id
   GOOGLE_APPLICATION_CREDENTIALS=/path/to/your/service-account-key.json
   ```

3. Create your encryption configuration file

4. Use the package in your code:
   ```typescript
   import { encryptionService } from '@vatsdev/encryption-decryption-poc';

   // Encrypt data
   const result = await encryptionService.encryptObject({
     modelName: 'User',
     data: { email: 'user@example.com', phone: '1234567890' },
     clientName: 'your-client'
   });

   // Decrypt data
   const decrypted = await encryptionService.decryptObject({
     modelName: 'User',
     data: result.encryptedData,
     entityKeyDetailsResult: result.keyMetadata
   });
   ```

## Usage Example

### Parameters

#### `modelName` (string)
The key identifier used in your `encryption.json` configuration file. This should match the model name you've configured for encryption.

#### `sensitiveData` (string)
The data you want to encrypt. This can be any string value that needs to be protected.

#### `entityKeyDetails` (object)
An object containing all required fields for encryption and decryption operations:

```typescript
interface EntityKeyDetails {
    locationId: string | null;    // Google Cloud KMS location ID
    keyRingId: string | null;     // KMS key ring identifier
    keyId: string | null;         // KMS key identifier
    secretId: string | null;      // Secret Manager secret ID
    encryptedDEK?: Buffer | null; // Encrypted Data Encryption Key
    keyVersion: string | null;    // KMS key version
}
```

### Example Usage

```typescript
import encryptionService from './services/encryptionService';

// Encrypt a field
const encryptedField = await encryptionService.encryptField(
    'model-name',
    'sensitive-data',
    entityKeyDetails
);

// Decrypt a field
const decryptedField = await encryptionService.decryptField(
    'model-name',
    'encrypted-data',
    entityKeyDetails
);
```

## Security Considerations

- All encryption keys are managed by Google Cloud KMS
- DEKs are encrypted before storage
- Automatic key rotation is supported
- Input validation and sanitization
- Comprehensive error handling
- No sensitive data in logs

## Development

1. Clone the repository
2. Install dependencies:
   ```bash
   npm install
   ```
3. Set up environment variables
4. Run tests:
   ```bash
   npm test
   ```

## Error Codes

### Configuration Errors
- `CONFIGURATION_MISSING_CONFIG`: Required configuration is missing
- `CONFIGURATION_MISSING_ENV_VAR`: Required environment variable is missing
- `CONFIGURATION_INITIALIZATION_ERROR`: Service initialization failed

### Encryption Errors
- `ENCRYPTION_FIELD_ENCRYPTION_ERROR`: Field encryption failed
- `ENCRYPTION_FIELD_DECRYPTION_ERROR`: Field decryption failed
- `ENCRYPTION_DEK_RESOLUTION_ERROR`: DEK resolution failed
- `ENCRYPTION_DEK_DECRYPTION_ERROR`: DEK decryption failed
- `ENCRYPTION_DEK_ENCRYPTION_ERROR`: DEK encryption failed
- `ENCRYPTION_SECRET_RETRIEVAL_ERROR`: Secret retrieval failed
- `ENCRYPTION_UNKNOWN_ERROR`: Unknown encryption error
- `ENCRYPTION_KEY_DETAILS_ERROR`: Key details retrieval failed
- `ENCRYPTION_KEY_VERSION_ERROR`: Key version error
- `ENCRYPTION_KEY_CREATION_ERROR`: Key creation failed
- `ENCRYPTION_CREATION_ERROR`: General creation error

### Validation Errors
- `VALIDATION_MISSING_REQUIRED_FIELD`: Required field is missing
- `VALIDATION_INVALID_DEK`: Invalid DEK format or content

## License

MIT 