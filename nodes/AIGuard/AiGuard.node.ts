import {
  ApplicationError,
  IDataObject,
  IExecuteFunctions,
  IN8nHttpFullResponse,
  INodeExecutionData,
  INodeType,
  INodeTypeDescription,
  NodeOperationError,
} from 'n8n-workflow';

interface AIGuardCredentials {
  apiKey: string;
  cloud: string;
  overrideUrl?: string;
  policyId?: string;
}

interface AIGuardScanPayload {
  content: string;
  direction: 'IN' | 'OUT';
  policyId?: number;
  transactionId?: string;
}

interface DetectorResponse {
  statusCode?: number;
  errorMsg?: string;
  triggered: boolean;
  action?: string;
  latency?: number;
  deviceType?: string;
  details?: Record<string, unknown>;
  severity?: string;
  contentHash?: { hashType?: string; hashValue?: string };
}

/**
 * Shared fields from ExecuteDetectionsPolicyResponse.
 * resolve-and-execute-policy additionally returns policyId, policyName, policyVersion.
 */
interface AIGuardResponse {
  transactionId: string;
  statusCode?: number;
  errorMsg?: string;
  detectorErrorCount?: number;
  action: 'ALLOW' | 'BLOCK' | 'DETECT';
  severity?: string;
  direction?: string;
  detectorResponses?: Record<string, DetectorResponse>;
  policyId?: number;
  policyName?: string;
  policyVersion?: string;
  maskedContent?: string;
}

class AIGuardScanner {
  constructor(private readonly helpers: IExecuteFunctions['helpers']) {}

  async executeScan(
    baseUrl: string,
    apiKey: string,
    payload: AIGuardScanPayload,
    timeout: number,
  ): Promise<AIGuardResponse> {
    const endpoint = payload.policyId
      ? '/v1/detection/execute-policy'
      : '/v1/detection/resolve-and-execute-policy';

    const body: Record<string, unknown> = {
      content: payload.content,
      direction: payload.direction,
    };

    if (payload.policyId !== undefined) {
      body.policyId = payload.policyId;
    }

    if (payload.transactionId !== undefined) {
      body.transactionId = payload.transactionId;
    }

    const url = `${baseUrl}${endpoint}`;

    try {
      const res = (await this.helpers.httpRequest({
        method: 'POST',
        url,
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body,
        json: true,
        timeout: timeout + 5000,
        returnFullResponse: true,
        ignoreHttpStatusErrors: true,
      })) as IN8nHttpFullResponse;

      const { statusCode } = res;
      let responseBody: unknown = res.body;

      if (typeof responseBody === 'string') {
        const raw = responseBody;
        try {
          responseBody = JSON.parse(raw) as unknown;
        } catch {
          throw new ApplicationError(`AI Guard body parse error: ${raw.slice(0, 200)}`);
        }
      }

      if (statusCode >= 200 && statusCode < 300) {
        return responseBody as AIGuardResponse;
      }

      const errText =
        typeof responseBody === 'object' && responseBody !== null
          ? JSON.stringify(responseBody).slice(0, 300)
          : String(responseBody).slice(0, 300);
      throw new ApplicationError(`AI Guard API returned ${statusCode}: ${errText}`);
    } catch (error) {
      if (error instanceof ApplicationError) {
        throw error;
      }
      const message = error instanceof Error ? error.message : String(error);
      if (/timeout|ETIMEDOUT|aborted/i.test(message)) {
        throw new ApplicationError('AI Guard request timed out');
      }
      throw new ApplicationError(`AI Guard request failed: ${message}`);
    }
  }
}

async function executeScanWithRetries(
  scanner: AIGuardScanner,
  baseUrl: string,
  apiKey: string,
  payload: AIGuardScanPayload,
  timeout: number,
  maxRetries: number,
): Promise<AIGuardResponse> {
  let lastError: unknown;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await scanner.executeScan(baseUrl, apiKey, payload, timeout);
    } catch (error) {
      lastError = error;
      if (attempt === maxRetries) {
        throw error;
      }
    }
  }
  throw lastError;
}

export class AiGuard implements INodeType {
  private static getBaseURL(cloud: string, overrideUrl?: string): string {
    if (overrideUrl && overrideUrl.trim() !== '') {
      return overrideUrl.replace(/\/$/, '');
    }
    return `https://api.${cloud}.zseclipse.net`;
  }

  private static extractTriggeredDetectors(
    detectorResponses?: Record<string, DetectorResponse>,
  ): string[] {
    const triggered: string[] = [];
    if (detectorResponses) {
      for (const [name, response] of Object.entries(detectorResponses)) {
        if (response.triggered) {
          triggered.push(name);
        }
      }
    }
    return triggered;
  }

  private static extractBlockingDetectors(
    detectorResponses?: Record<string, DetectorResponse>,
  ): string[] {
    const blocking: string[] = [];
    if (detectorResponses) {
      for (const [name, response] of Object.entries(detectorResponses)) {
        if (response.action && response.action.toUpperCase() === 'BLOCK') {
          blocking.push(name);
        }
      }
    }
    return blocking;
  }

  private static validateContentSize(content: string): void {
    const contentSize = Buffer.byteLength(content, 'utf8');
    const maxSize = 5 * 1024 * 1024;

    if (contentSize > maxSize) {
      throw new ApplicationError(
        `Content size (${Math.round(contentSize / 1024 / 1024)}MB) exceeds maximum limit (5MB)`,
      );
    }
  }

  description: INodeTypeDescription = {
    displayName: 'Zscaler AI Guard',
    name: 'aiGuard',
    icon: 'file:aiguard.svg',
    group: ['transform'],
    version: 1,
    subtitle: '={{$parameter["operation"]}}',
    description: 'Scan AI prompts and responses for security threats using Zscaler AI Guard',
    defaults: {
      name: 'AI Guard',
    },
    inputs: ['main'],
    outputs: ['main'],
    credentials: [
      {
        name: 'aiGuardApi',
        required: true,
      },
    ],
    properties: [
      {
        displayName: 'Operation',
        name: 'operation',
        type: 'options',
        noDataExpression: true,
        options: [
          {
            name: 'Prompt Scan',
            value: 'promptScan',
            description: 'Scan user input/prompts for security threats',
            action: 'Scan a prompt for security threats',
          },
          {
            name: 'Response Scan',
            value: 'responseScan',
            description: 'Scan AI-generated responses for policy violations',
            action: 'Scan a response for policy violations',
          },
          {
            name: 'Dual Scan',
            value: 'dualScan',
            description: 'Scan both prompt and response in sequence',
            action: 'Perform dual scanning of prompt and response',
          },
        ],
        default: 'promptScan',
      },
      {
        displayName: 'Content',
        name: 'content',
        type: 'string',
        requiresDataPath: 'single',
        typeOptions: {
          rows: 4,
        },
        default: '',
        required: true,
        description: 'The content to scan for security threats',
        displayOptions: {
          show: {
            operation: ['promptScan', 'responseScan'],
          },
        },
      },
      {
        displayName: 'Prompt Content',
        name: 'promptContent',
        type: 'string',
        requiresDataPath: 'single',
        typeOptions: {
          rows: 3,
        },
        default: '',
        required: true,
        description: 'The prompt content to scan',
        displayOptions: {
          show: {
            operation: ['dualScan'],
          },
        },
      },
      {
        displayName: 'Response Content',
        name: 'responseContent',
        type: 'string',
        requiresDataPath: 'single',
        typeOptions: {
          rows: 3,
        },
        default: '',
        required: true,
        description: 'The response content to scan',
        displayOptions: {
          show: {
            operation: ['dualScan'],
          },
        },
      },
      {
        displayName: 'Additional Options',
        name: 'additionalOptions',
        type: 'collection',
        placeholder: 'Add Option',
        default: {},
        options: [
          {
            displayName: 'AI Model',
            name: 'aiModel',
            type: 'string',
            default: 'n8n-integration',
            description: 'AI model identifier for metadata',
          },
          {
            displayName: 'Application Name',
            name: 'applicationName',
            type: 'string',
            default: 'n8n-workflow',
            description: 'Application name for audit trails',
          },
          {
            displayName: 'Environment',
            name: 'environment',
            type: 'string',
            default: '',
            placeholder: 'e.g., production, staging, development',
            description: 'Environment identifier for attribution and tracking (optional)',
          },
          {
            displayName: 'Max Retries',
            name: 'maxRetries',
            type: 'number',
            default: 3,
            description: 'Maximum number of retry attempts for failed requests',
          },
          {
            displayName: 'Policy ID Override',
            name: 'policyIdOverride',
            type: 'string',
            default: '',
            description:
              'Override the default policy ID from credentials. Leave empty to use credential policy or auto-resolution.',
          },
          {
            displayName: 'Timeout (Ms)',
            name: 'timeout',
            type: 'number',
            default: 30000,
            description: 'Request timeout in milliseconds',
          },
          {
            displayName: 'Transaction ID',
            name: 'transactionId',
            type: 'string',
            default: '',
            description: 'Custom transaction ID for tracking. If empty, one will be generated.',
          },
          {
            displayName: 'User ID',
            name: 'userId',
            type: 'string',
            default: 'n8n-user',
            description: 'User identifier for audit trails',
          },
        ],
      },
    ],
  };

  async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
    const items = this.getInputData();
    const returnData: INodeExecutionData[] = [];
    const credentials = (await this.getCredentials('aiGuardApi')) as unknown as AIGuardCredentials;

    const baseUrl = AiGuard.getBaseURL(credentials.cloud, credentials.overrideUrl);

    for (let i = 0; i < items.length; i++) {
      try {
        const operation = this.getNodeParameter('operation', i) as string;
        const additionalOptions = this.getNodeParameter('additionalOptions', i, {}) as IDataObject;

        const workflow = this.getWorkflow();
        const context = {
          workflowName: workflow?.name || '',
          workflowId: workflow?.id || '',
          executionId: this.getExecutionId() || '',
          executionMode: this.getMode() || '',
        };

        const transactionId = (additionalOptions.transactionId as string) || '';
        const environment = (additionalOptions.environment as string) || '';
        const timeout = (additionalOptions.timeout as number) || 30000;
        const rawMaxRetries = (additionalOptions.maxRetries as number) || 3;
        const maxRetries = Math.min(rawMaxRetries, 6);
        const policyIdOverride = (additionalOptions.policyIdOverride as string) || '';
        const policyIdStr = policyIdOverride || credentials.policyId || '';

        const scanner = new AIGuardScanner(this.helpers);

        const buildPayload = (content: string, direction: 'IN' | 'OUT'): AIGuardScanPayload => {
          const payload: AIGuardScanPayload = { content, direction };
          if (policyIdStr) {
            const parsed = parseInt(policyIdStr, 10);
            if (!isNaN(parsed)) {
              payload.policyId = parsed;
            }
          }
          if (transactionId) {
            payload.transactionId = transactionId;
          }
          return payload;
        };

        let scanResult: AIGuardResponse;

        switch (operation) {
          case 'promptScan': {
            const content = this.getNodeParameter('content', i) as string;
            AiGuard.validateContentSize(content);
            scanResult = await executeScanWithRetries(
              scanner,
              baseUrl,
              credentials.apiKey,
              buildPayload(content, 'IN'),
              timeout,
              maxRetries,
            );
            break;
          }
          case 'responseScan': {
            const content = this.getNodeParameter('content', i) as string;
            AiGuard.validateContentSize(content);
            scanResult = await executeScanWithRetries(
              scanner,
              baseUrl,
              credentials.apiKey,
              buildPayload(content, 'OUT'),
              timeout,
              maxRetries,
            );
            break;
          }
          case 'dualScan': {
            const promptContent = this.getNodeParameter('promptContent', i) as string;
            const responseContent = this.getNodeParameter('responseContent', i) as string;

            AiGuard.validateContentSize(promptContent);
            AiGuard.validateContentSize(responseContent);

            const promptResult = await executeScanWithRetries(
              scanner,
              baseUrl,
              credentials.apiKey,
              buildPayload(promptContent, 'IN'),
              timeout,
              maxRetries,
            );

            if (promptResult.action === 'BLOCK') {
              scanResult = promptResult;
              break;
            }

            const responseResult = await executeScanWithRetries(
              scanner,
              baseUrl,
              credentials.apiKey,
              buildPayload(responseContent, 'OUT'),
              timeout,
              maxRetries,
            );

            scanResult = {
              ...responseResult,
              promptScan: promptResult,
            } as AIGuardResponse & { promptScan: AIGuardResponse };
            break;
          }
          default:
            throw new NodeOperationError(this.getNode(), `Unknown operation: ${operation}`);
        }

        const triggeredDetectors = AiGuard.extractTriggeredDetectors(scanResult.detectorResponses);
        const blockingDetectors = AiGuard.extractBlockingDetectors(scanResult.detectorResponses);

        const outputData: IDataObject = {
          operation,
          ...scanResult,
          severity: scanResult.severity || 'NONE',
          detectors: triggeredDetectors,
          blockingDetectors,
          blocked: scanResult.action === 'BLOCK',
          ...(context.workflowId && { workflowId: context.workflowId }),
          ...(context.workflowName && {
            workflowName: context.workflowName,
          }),
          ...(context.executionId && {
            executionId: context.executionId,
          }),
          ...(context.executionMode && {
            executionMode: context.executionMode,
          }),
          ...(environment && { environment }),
          timestamp: new Date().toISOString(),
        };

        returnData.push({
          json: outputData,
          pairedItem: { item: i },
        });
      } catch (error) {
        if (this.continueOnFail()) {
          returnData.push({
            json: {
              error: error instanceof Error ? error.message : 'Unknown error',
              action: 'BLOCK',
              blocked: true,
              timestamp: new Date().toISOString(),
            },
            pairedItem: { item: i },
          });
        } else {
          throw error;
        }
      }
    }

    return [returnData];
  }
}
