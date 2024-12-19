# Core-API

API for reading and writing the DynamoDB tables

## Directory structure

* **event/** - Event processing
* **item/** - Deployment item table
* **lib/** - Third-party libraries
* **tests/** - Directory containing various test data files
* **main.py** - Lambda entry point (handler method). A good place to start.

## Description

This is the "TOP" level library.

Example of hierarchy:

Layer 1 - Core Framework

Layer 2 - Core-Start-Runner (this module)

Layer 3 - AWS Core, Azure Core, VMWare Core, GCP Core

Layer 4 - SCK Core Module / API

Layer 5 - SCK Command Line

From the SCK Command line "core" modules is executed which determines targets and loads
the appropriate target libraries.  The target libraries will then use this core
framework library with helper functions.


## Configuration

If you include this module in your project, you are REQUIRED to produce a configuration
file called "config.py" and put that configration file in the root of your project.

### Core-Automation Configuration Variables

| Variable Name        | Type    | Default Value | Description                                                  | Example                |
|----------------------|---------|---------------|--------------------------------------------------------------|------------------------|
| `ENVIRONMENT`        | String  | None          | Core Automation Operating Environment: prod, nonprod, or dev | `prod`                 |
| `LCOAL_MODE`         | Boolean | None          | Enable local operation mode for the app.                     | `True` or `False`      |
| `API_LAMBDA_ARN`     | String  | None          | Secret API key for authentication.                           | `API_KEY=your-api-key` |
| `OUTPUT_PATH`        | String  | None          |                                                              |                        |
| `PLATFORM_PATH`      | String  | None          |                                                              |                        |
| `ENFORCE_VALIDATION` | String  | None          |                                                              |                        |
| `DYNAMODB_HOST`      | String  | None          |                                                              |                        |
| `DYNAMODB_REAGION`   | String  | None          |                                                              |                        |
| `EVENT_TABLE_NAME`   | String  | None          |                                                              |                        |
| `BASE_DIR`           | String  | None          | The folder where the sub-folder 'compiler' is located        |                        |

These above values are required by various modules.  Please generate this config.py file and put in the ROOT of your application
during your application deployment.

# Core API Lamdas

This is composed of 2 stacks

```shell
sck upload plan -p core-automation-master-api -a db-resoruces -b prd-sin -n 1
sck apply -p core-automation-master-api -a db-resoruces -b prd-sin -n 1
```

```shell
# Deploy the stack without a plan
sck upload deploy -p core-automation-master-api -a lambda-resoruces -b prd-sin -n 1
```

# Dynamodb

## DynamoDB Schema Definition

### Common Fields (Applicable to All Tables)
- `prn`: Partition key (String)
- `name`: (String)
- `created_at`: (String or Number, representing a timestamp)
- `updated_at`: (String or Number, representing a timestamp)

### Table Definitions

#### Portfolio Table
- **Primary Key**: `prn`
- **Attributes**:
    - `contact_email`: (String)

#### App Table
- **Primary Key**: `prn`
- **Attributes**:
    - `portfolio_prn`: (String)
    - `contact_email`: (String)
- **Global Secondary Index (GSI)**:
    - **Name**: `PortfolioIndex`
    - **Key**: `portfolio_prn`

#### Branch Table
- **Primary Key**: `prn`
- **Attributes**:
    - `portfolio_prn`: (String)
    - `app_prn`: (String)
    - `short_name`: (String)
- **GSI**:
    - **Name**: `AppIndex`
    - **Key**: `app_prn`

#### Build Table
- **Primary Key**: `prn`
- **Attributes**:
    - `portfolio_prn`: (String)
    - `app_prn`: (String)
    - `branch_prn`: (String)
    - `status`: (String)
    - `message`: (String)
    - `details`: (Map or String)
- **GSI**:
    - **Name**: `BranchIndex`
    - **Key**: `branch_prn`

#### Component Table
- **Primary Key**: `prn`
- **Attributes**:
    - `portfolio_prn`: (String)
    - `app_prn`: (String)
    - `branch_prn`: (String)
    - `build_prn`: (String)
    - `status`: (String)
    - `message`: (String)
- **GSI**:
    - **Name**: `BuildIndex`
    - **Key**: `build_prn`

#### Event Table
- **Primary Key**: `prn`
- **Sort Key**: `timestamp`
- **Attributes**:
    - `status`: (String)
    - `message`: (String)
    - `details`: (Map or String)

### New Schema Definitions

- New schema definitions like `items`, `events`, etc., are more complex and involve the
use of composite keys and additional indexes for querying purposes. These schemas are designed
to optimize specific query patterns mentioned in the "Desired queries" section, using Partition
Keys (PK), Sort Keys (SK), Local Secondary Indexes (LSI), and Global Secondary Indexes (GSI) to
facilitate different types of queries.
