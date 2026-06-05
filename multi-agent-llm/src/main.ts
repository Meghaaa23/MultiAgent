import { Component, signal, ChangeDetectionStrategy, Injectable, ViewChild, ElementRef, NgZone } from '@angular/core';
import { bootstrapApplication } from '@angular/platform-browser';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApplicationConfig, importProvidersFrom } from '@angular/core';
import { HttpClientModule, HttpClient } from '@angular/common/http';
import { firstValueFrom, Observable, Subject } from 'rxjs';

export const appConfig: ApplicationConfig = {
  providers: [importProvidersFrom(HttpClientModule)]
};

// =============================================================================
// Interfaces
// =============================================================================

interface Document {
  filename: string;
  chunk_count: number;
}

interface ReportSection {
  id: string;
  title: string;
  content: string;
}

interface ChatMessage {
  sender: string;
  text: string;
  reportSections?: ReportSection[];
  metadata?: {
    filesSearched?: any;
    filesProcessed?: string[];
    searchScope?: string;
    conversationMessages?: number;
    teamPersistent?: boolean;
  };
}

interface ProgressEvent {
  phase: string;
  step: number;
  total_steps: number;
  message: string;
  percent: number;
}

interface StreamResult {
  query: string;
  answer: string;
  report?: string;
  report_sections?: ReportSection[];
  reasoning_chain?: any;
  web_scan_performed?: boolean;
  target_url?: string | null;
  cached?: boolean;
  files_searched?: any;
  files_processed?: string[];
  search_scope?: string;
  conversation_messages?: number;
  team_persistent?: boolean;
}

interface StreamError {
  message: string;
  phase: string;
}

type StreamEvent =
  | { type: 'progress'; data: ProgressEvent }
  | { type: 'result'; data: StreamResult }
  | { type: 'error'; data: StreamError };

// =============================================================================
// API Service (with SSE streaming support)
// =============================================================================

@Injectable({ providedIn: 'root' })
export class ApiService {
  private sessionId: string = '';

  constructor(private http: HttpClient, private ngZone: NgZone) {
    this.generateSessionId();
  }

  private generateSessionId(): string {
    if (!this.sessionId) {
      this.sessionId = `session-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      console.log(' Session ID:', this.sessionId);
    }
    return this.sessionId;
  }

  getSessionId(): string {
    return this.sessionId;
  }

  resetSession(): void {
    this.sessionId = '';
    this.generateSessionId();
  }

  getDocuments(): Promise<{ total_documents: number; documents: Document[] }> {
    return firstValueFrom(
      this.http.get<{ total_documents: number; documents: Document[] }>('/api/documents')
    );
  }

  uploadFiles(files: File[] | FileList): Promise<any> {
    const fd = new FormData();
    const fileArray = Array.from(files) as File[];
    fileArray.forEach((file: File) => fd.append('files', file));
    return firstValueFrom(this.http.post<any>('/api/uploadfile/', fd));
  }

  // Original non-streaming query (kept as fallback)
  queryDocument(
    question: string,
    filenames: string[],
    uploadedFiles: string[] = [],
    useAllDocs: boolean = false,
    sessionId?: string,
    authCookie: string = ''
  ): Promise<any> {
    const payload: any = {
      question,
      filenames,
      uploaded_files: uploadedFiles,
      use_all_docs: useAllDocs,
      session_id: sessionId || this.getSessionId()
    };
    if (authCookie) payload.auth_cookie = authCookie;
    return firstValueFrom(
      this.http.post<any>('/api/query/', payload, {
        headers: { 'Content-Type': 'application/json' }
      })
    );
  }

  // =========================================================================
  // SSE Streaming Query
  // =========================================================================
  queryDocumentStream(
    question: string,
    filenames: string[],
    uploadedFiles: string[] = [],
    useAllDocs: boolean = false,
    sessionId?: string,
    authCookie: string = ''
  ): Observable<StreamEvent> {
    const subject = new Subject<StreamEvent>();

    const payload: any = {
      question,
      filenames,
      uploaded_files: uploadedFiles,
      use_all_docs: useAllDocs,
      session_id: sessionId || this.getSessionId()
    };
    if (authCookie) payload.auth_cookie = authCookie;

    this.consumeSSE('/api/query/stream', payload, subject);
    return subject.asObservable();
  }

  private async consumeSSE(
    url: string,
    body: any,
    subject: Subject<StreamEvent>
  ): Promise<void> {
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });

      if (!response.ok) {
        this.ngZone.run(() =>
          subject.error(new Error(`HTTP ${response.status}: ${response.statusText}`))
        );
        return;
      }

      const reader = response.body!.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();

        if (done) {
          if (buffer.trim()) this.parseSSE(buffer, subject);
          this.ngZone.run(() => subject.complete());
          break;
        }

        buffer += decoder.decode(value, { stream: true });
        const messages = buffer.split('\n\n');
        buffer = messages.pop() || '';

        for (const msg of messages) {
          if (msg.trim()) this.parseSSE(msg, subject);
        }
      }
    } catch (err) {
      this.ngZone.run(() => subject.error(err));
    }
  }

  private parseSSE(message: string, subject: Subject<StreamEvent>): void {
    let eventType = 'message';
    let data = '';

    for (const line of message.split('\n')) {
      if (line.startsWith('event: ')) eventType = line.slice(7).trim();
      else if (line.startsWith('data: ')) data += line.slice(6);
    }

    if (!data) return;

    try {
      const parsed = JSON.parse(data);
      this.ngZone.run(() => {
        if (eventType === 'progress') {
          subject.next({ type: 'progress', data: parsed as ProgressEvent });
        } else if (eventType === 'result') {
          subject.next({ type: 'result', data: parsed as StreamResult });
        } else if (eventType === 'error') {
          subject.next({ type: 'error', data: parsed as StreamError });
        }
      });
    } catch (e) {
      console.error('SSE parse error:', data, e);
    }
  }

  clearSession(sessionId?: string): Promise<any> {
    const sid = sessionId || this.getSessionId();
    return firstValueFrom(this.http.post<any>(`/api/clear-session/${sid}`, {}));
  }

  getModelSettings(): Promise<any> {
    return firstValueFrom(this.http.get<any>('/api/settings/model'));
  }

  switchProvider(provider: 'local' | 'azure'): Promise<any> {
    return firstValueFrom(
      this.http.post<any>('/api/settings/model', { provider }, {
        headers: { 'Content-Type': 'application/json' }
      })
    );
  }
}

// =============================================================================
// App Component
// =============================================================================

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
  <div class="min-h-screen bg-gray-900 text-white flex">
    <!-- ================================================================= -->
    <!-- Sidebar - Document Library                                        -->
    <!-- ================================================================= -->
    <div class="w-80 bg-gray-800 border-r border-gray-700 flex flex-col">
      <div class="p-4 border-b border-gray-700">
        <h2 class="text-lg font-semibold text-white flex items-center gap-2">
           Document Library
        </h2>
        <button
          (click)="loadDocuments()"
          [disabled]="loadingDocuments()"
          class="mt-2 text-sm text-blue-400 hover:text-blue-300 flex items-center gap-1 disabled:opacity-50">
            {{ loadingDocuments() ? 'Loading...' : 'Refresh' }}
        </button>
      </div>

      <!-- Search All Toggle -->
      <div class="p-4 border-b border-gray-700 bg-gray-750">
        <label class="flex items-center gap-2 cursor-pointer">
          <input type="checkbox" [(ngModel)]="searchAllDocs" (change)="onSearchAllChange()"
                 class="w-4 h-4 text-blue-600 rounded" />
          <span class="text-sm font-medium text-gray-300">Search All Documents</span>
        </label>
        <p class="text-xs text-gray-500 mt-1 ml-6">
          {{ searchAllDocs ? 'Querying entire database' : 'Select specific documents' }}
        </p>
      </div>

      <!-- Available Documents List -->
      <div class="flex-1 overflow-y-auto p-4">
        <h3 class="text-sm font-semibold text-gray-400 mb-2">
          Available Documents ({{ availableDocuments().length }})
        </h3>

        <div *ngIf="availableDocuments().length === 0" class="text-center py-8 text-gray-500">
          <p class="text-sm">No documents uploaded yet</p>
          <p class="text-xs mt-1">Upload files below</p>
        </div>

        <div class="space-y-2">
          <div *ngFor="let doc of availableDocuments()"
               (click)="!searchAllDocs && toggleDocumentSelection(doc.filename)"
               class="p-3 rounded-lg border transition-all cursor-pointer"
               [ngClass]="{
                 'bg-gray-700 border-gray-600 opacity-50 cursor-not-allowed': searchAllDocs,
                 'bg-blue-900 border-blue-500': !searchAllDocs && isDocumentSelected(doc.filename),
                 'bg-gray-750 border-gray-600 hover:border-blue-500': !searchAllDocs && !isDocumentSelected(doc.filename)
               }">
            <div class="flex items-start gap-2">
              <div class="mt-1">{{ getFileIcon(doc.filename) }}</div>
              <div class="flex-1 min-w-0">
                <p class="text-sm font-medium text-white truncate">{{ doc.filename }}</p>
                <p class="text-xs text-gray-400">{{ doc.chunk_count }} chunks</p>
              </div>
              <div *ngIf="!searchAllDocs && isDocumentSelected(doc.filename)"
                   class="w-5 h-5 bg-blue-600 rounded-full flex items-center justify-center">
                <span class="text-white text-xs">✓</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Upload Section -->
      <div class="p-4 border-t border-gray-700">
        <input #fileInput type="file" multiple (change)="onFilesSelected($event)"
               class="hidden" accept=".pdf,.png,.jpg,.jpeg,.mp3,.wav" />
        <button (click)="fileInput.click()"
                class="w-full py-2 px-4 bg-blue-600 hover:bg-blue-700 rounded-lg font-medium transition-colors">
           Upload New Documents
        </button>
        <div *ngIf="filesToUpload().length > 0" class="mt-3 space-y-2">
          <p class="text-xs font-semibold text-gray-400">Ready to upload ({{ filesToUpload().length }}):</p>
          <div *ngFor="let f of filesToUpload(); let i = index"
               class="flex items-center gap-2 p-2 bg-green-900 rounded border border-green-700">
            <span class="text-xs flex-1 truncate">{{ f.name }}</span>
            <button (click)="removeFile(i)" class="text-red-400 hover:text-red-300">x</button>
          </div>
          <p class="text-xs text-gray-500 italic"> Files upload when you send question</p>
        </div>
      </div>
    </div>

    <!-- ================================================================= -->
    <!-- Main Chat Area                                                    -->
    <!-- ================================================================= -->
    <div class="flex-1 flex flex-col">
      <!-- Header -->
      <div class="bg-gray-800 border-b border-gray-700 p-4 flex justify-between items-center">
        <div>
          <h1 class="text-xl font-bold text-white flex items-center gap-2">
             Multi-Agent Threat Modeling System
          </h1>
          <p class="text-sm text-gray-400 mt-1">{{ getHeaderStatus() }}</p>
        </div>
        <div class="flex items-center gap-3">
          <!-- LLM Provider Toggle -->
          <div class="flex items-center gap-2 px-3 py-2 bg-gray-700 rounded-lg border border-gray-600">
            <span class="text-xs text-gray-400 font-medium">LLM:</span>
            <button
              (click)="toggleProvider()"
              [disabled]="isSwitchingProvider() || isLoading()"
              class="flex items-center gap-1.5 text-xs font-semibold px-2 py-1 rounded transition-all disabled:opacity-50 disabled:cursor-not-allowed"
              [ngClass]="{
                'bg-orange-600 hover:bg-orange-500 text-white': currentProvider() === 'local',
                'bg-blue-600 hover:bg-blue-500 text-white': currentProvider() === 'azure'
              }"
              [title]="'Switch to ' + (currentProvider() === 'azure' ? 'Local Qwen' : 'Azure OpenAI')">
              <span *ngIf="isSwitchingProvider()">...</span>
              <span *ngIf="!isSwitchingProvider()">
                {{ currentProvider() === 'azure' ? 'Azure OpenAI' : 'Local Qwen' }}
              </span>
            </button>
          </div>

          <button (click)="clearChat()"
                  class="px-4 py-2 text-red-400 hover:bg-red-900 rounded-lg transition-colors text-sm font-medium">
             Clear Chat
          </button>
        </div>
      </div>

      <!-- Messages -->
      <div #scrollContainer class="flex-1 overflow-y-auto p-4 space-y-4">
        <!-- Welcome -->
        <div *ngIf="chatMessages().length === 1" class="text-center py-12">
          <div class="text-6xl mb-4"></div>
          <h3 class="text-lg font-semibold text-gray-300 mb-2">Welcome to Multi-Agent Threat Modeling System</h3>
        </div>

        <!-- Chat Messages -->
        <div *ngFor="let msg of chatMessages(); let msgIdx = index" class="flex"
             [ngClass]="{ 'justify-end': msg.sender === 'user', 'justify-start': msg.sender === 'agent' }">
          <div class="rounded-lg p-4"
               [ngClass]="{
                 'max-w-2xl bg-blue-600 text-white': msg.sender === 'user',
                 'max-w-5xl bg-gray-800 text-white border border-gray-700': msg.sender === 'agent'
               }">

            <!-- Plain text (user messages and non-section agent messages) -->
            <div *ngIf="!msg.reportSections || msg.reportSections.length === 0"
                 class="whitespace-pre-wrap">{{ msg.text }}</div>

            <!-- Accordion sections for scan reports -->
            <div *ngIf="msg.reportSections && msg.reportSections.length > 0" class="space-y-1.5">
              <div *ngFor="let section of msg.reportSections"
                   class="rounded-lg overflow-hidden border"
                   [ngClass]="{
                     'border-blue-500': getActiveSection(msgIdx) === section.id,
                     'border-gray-700': getActiveSection(msgIdx) !== section.id
                   }">

                <!-- Clickable section heading -->
                <button class="w-full flex items-center justify-between px-4 py-2.5 text-left transition-colors"
                        [ngClass]="{
                          'bg-blue-900 text-blue-200': getActiveSection(msgIdx) === section.id,
                          'bg-gray-750 hover:bg-gray-700 text-gray-300': getActiveSection(msgIdx) !== section.id
                        }"
                        (click)="toggleSection(msgIdx, section.id)">
                  <span class="text-sm font-semibold">{{ section.title }}</span>
                  <span class="text-xs ml-3 flex-shrink-0"
                        [ngClass]="{'text-blue-300': getActiveSection(msgIdx) === section.id, 'text-gray-500': getActiveSection(msgIdx) !== section.id}">
                    {{ getActiveSection(msgIdx) === section.id ? '▲' : '▼' }}
                  </span>
                </button>

                <!-- Section content (only visible when active) -->
                <div *ngIf="getActiveSection(msgIdx) === section.id"
                     class="px-4 py-3 bg-gray-900 border-t border-gray-700 whitespace-pre-wrap text-xs leading-relaxed font-mono text-gray-200 max-h-96 overflow-y-auto">
                  {{ section.content }}
                </div>
              </div>
            </div>

            <!-- Metadata badges -->
            <div *ngIf="msg.metadata" class="mt-3 pt-3 border-t border-gray-600 text-xs text-gray-400">
              <span *ngIf="msg.metadata!.teamPersistent"
                    class="inline-block px-2 py-1 bg-purple-900 text-purple-300 rounded mr-2">
                 AutoGen Memory
              </span>
              <span *ngIf="msg.metadata!.conversationMessages && msg.metadata!.conversationMessages > 0"
                    class="inline-block px-2 py-1 bg-indigo-900 text-indigo-300 rounded mr-2">
                 {{ msg.metadata!.conversationMessages }} messages
              </span>
              <span *ngIf="msg.metadata!.filesProcessed && msg.metadata!.filesProcessed.length > 0"
                    class="inline-block px-2 py-1 bg-green-900 text-green-300 rounded mr-2">
                 {{ msg.metadata!.filesProcessed.join(', ') }}
              </span>
              <span *ngIf="msg.metadata!.searchScope"
                    class="inline-block px-2 py-1 bg-blue-900 text-blue-300 rounded">
                {{ msg.metadata!.searchScope === 'all_documents' ? ' All Docs' : ' Selected' }}
              </span>
            </div>
          </div>
        </div>

        <!-- ============================================================= -->
        <!-- STREAMING PROGRESS INDICATOR (replaces the bouncing dots)     -->
        <!-- ============================================================= -->
        <!-- STREAMING PROGRESS INDICATOR -->
        <div *ngIf="isLoading()" class="flex justify-start">
          <div class="w-full max-w-2xl rounded-xl border border-gray-700 overflow-hidden"
              style="background: linear-gradient(135deg, #111827 0%, #1a1a2e 50%, #111827 100%);">

            <!-- Phase Header -->
            <div class="px-5 pt-4 pb-2 flex items-center justify-between">
              <div class="flex items-center gap-3">
                
                <div>
                  <div class="text-xs font-bold tracking-widest uppercase"
                      style="color: #60a5fa; letter-spacing: 0.12em;">
                    {{ getPhaseName(analysisPhase()) }}
                  </div>
                  <div class="text-sm text-gray-300 mt-0.5 transition-all duration-300">
                    {{ analysisMessage() || 'Initializing...' }}
                  </div>
                </div>
              </div>
              <div class="text-right">
                <span class="text-2xl font-bold tabular-nums" style="color: #60a5fa;">
                  {{ analysisPercent() }}%
                </span>
              </div>
            </div>

            <!-- Progress Bar -->
            <div class="mx-5 mb-4 h-2 rounded-full overflow-hidden" style="background: #1e293b;">
              <div class="h-full rounded-full transition-all duration-700 ease-out"
                  [style.width.%]="analysisPercent()"
                  style="background: linear-gradient(90deg, #1d4ed8, #3b82f6, #93c5fd);
                          box-shadow: 0 0 16px rgba(59,130,246,0.6);">
              </div>
            </div>

            <!-- Step Timeline — fixed min-height so layout doesn't jump -->
            <div class="px-5 pb-4 space-y-1.5" style="min-height: 120px;">
              <div *ngFor="let step of analysisSteps(); let i = index; let last = last"
                  class="flex items-start gap-2 text-xs transition-all duration-300"
                  [style.opacity]="last ? '1' : (i === analysisSteps().length - 2 ? '0.65' : '0.35')">

                <!-- Icon -->
                <span *ngIf="!last" class="mt-0.5 text-green-400 flex-shrink-0">✓</span>
                <span *ngIf="last"
                      class="mt-1.5 flex-shrink-0 inline-block w-2 h-2 rounded-full animate-pulse"
                      style="background: #60a5fa; box-shadow: 0 0 8px #60a5fa; min-width: 8px;">
                </span>

                <!-- Text -->
                <span [style.color]="last ? '#bfdbfe' : '#4b5563'">{{ step }}</span>
              </div>

              <!-- Animated dots when no steps yet -->
              <div *ngIf="analysisSteps().length === 0"
                  class="flex items-center gap-1.5 text-xs" style="color: #4b5563;">
                <span class="inline-block w-1.5 h-1.5 rounded-full animate-bounce"
                      style="background:#3b82f6; animation-delay:0ms"></span>
                <span class="inline-block w-1.5 h-1.5 rounded-full animate-bounce"
                      style="background:#3b82f6; animation-delay:150ms"></span>
                <span class="inline-block w-1.5 h-1.5 rounded-full animate-bounce"
                      style="background:#3b82f6; animation-delay:300ms"></span>
                <span class="ml-1">Connecting...</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Input Area -->
      <div class="bg-gray-800 border-t border-gray-700 p-4">
        <div class="space-y-2">
          <textarea #promptInput rows="3"
                    placeholder="Ask a question about your documents..."
                    (keypress)="onKeyPress($event, promptInput.value)"
                    [disabled]="isLoading()"
                    class="w-full px-4 py-3 border border-gray-600 rounded-lg bg-gray-900 text-white placeholder-gray-500 focus:border-blue-500 disabled:bg-gray-700 disabled:cursor-not-allowed resize-none">
          </textarea>
          <!-- Auth cookie toggle -->
          <div class="flex items-center gap-2">
            <button (click)="showAuthInput = !showAuthInput"
                    class="text-xs px-3 py-1 rounded border transition-colors"
                    [ngClass]="authCookie ? 'border-green-500 text-green-400 bg-green-900' : 'border-gray-600 text-gray-400 hover:border-gray-500'">
              {{ authCookie ? ' Authenticated' : ' Add Auth Cookie' }}
            </button>
            <button *ngIf="authCookie" (click)="authCookie = ''; showAuthInput = false"
                    class="text-xs text-red-400 hover:text-red-300">clear</button>
          </div>
          <input *ngIf="showAuthInput"
                 type="password"
                 placeholder="Paste session cookie (e.g. sessionid=abc123; csrftoken=xyz)"
                 [(ngModel)]="authCookie"
                 class="w-full px-3 py-2 text-xs border border-yellow-600 rounded bg-gray-900 text-yellow-200 placeholder-gray-600 focus:border-yellow-400 font-mono">

          <button (click)="handleQuery(promptInput.value); promptInput.value = ''"
                  [disabled]="isLoading() || !promptInput.value.trim()"
                  class="w-full px-6 py-3 bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 text-white rounded-lg disabled:from-gray-600 disabled:to-gray-600 disabled:cursor-not-allowed transition-all font-medium">
            {{ isLoading() ? ' Analyzing...' : ' Submit Query' }}
          </button>
        </div>
        <p *ngIf="filesToUpload().length > 0" class="text-xs text-green-400 mt-2 font-medium">
           {{ filesToUpload().length }} new file(s) will be uploaded with your question
        </p>
        <p *ngIf="chatMessages().length > 1 && !isLoading()" class="text-xs text-gray-500 mt-2">
           Conversation memory active - AutoGen remembers context
        </p>
      </div>

      <div *ngIf="uploadError()" class="mx-4 mb-4 text-red-300 bg-red-900 border border-red-700 p-4 rounded-lg">
        <p class="font-semibold"> Error</p>
        <p>{{ uploadError() }}</p>
      </div>
    </div>
  </div>
  `,
  styles: [`
    :host { display: block; }
  `],
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class AppComponent {
  constructor(private apiService: ApiService) {
    this.loadDocuments();
    this.loadModelSettings();
  }

  @ViewChild('promptInput') promptInputRef?: ElementRef<HTMLTextAreaElement>;
  @ViewChild('scrollContainer') scrollContainerRef?: ElementRef<HTMLDivElement>;

  // Chat state
  chatMessages = signal<ChatMessage[]>([{
    sender: 'agent',
    text: 'Hello! Upload documents or select from library and ask questions!'
  }]);
  filesToUpload = signal<File[]>([]);
  uploadError = signal<string | null>(null);
  isLoading = signal(false);

  // Document state
  availableDocuments = signal<Document[]>([]);
  selectedDocuments = signal<string[]>([]);
  searchAllDocs = false;
  uploadedInSession = signal<string[]>([]);
  loadingDocuments = signal(false);

  // LLM provider state
  currentProvider = signal<'local' | 'azure'>('azure');
  currentModelName = signal<string>('');
  isSwitchingProvider = signal(false);

  // Streaming progress state (signals for OnPush)
  analysisPhase = signal<string>('');
  analysisMessage = signal<string>('');
  analysisPercent = signal<number>(0);
  analysisSteps = signal<string[]>([]);

  // Optional session cookie for authenticated scanning
  authCookie = '';
  showAuthInput = false;

  // Per-message active section tracking: message index → open section id (null = all closed)
  activeSections = signal<Map<number, string | null>>(new Map());

  toggleSection(msgIdx: number, sectionId: string): void {
    const current = this.activeSections().get(msgIdx);
    const next = new Map(this.activeSections());
    next.set(msgIdx, current === sectionId ? null : sectionId);
    this.activeSections.set(next);
  }

  getActiveSection(msgIdx: number): string | null {
    return this.activeSections().get(msgIdx) ?? null;
  }

  private readonly allowedMimeTypes: Record<string, string> = {
    'application/pdf': 'pdf',
    'image/png': 'png',
    'image/jpeg': 'jpg',
    'image/jpg': 'jpg',
    'audio/mpeg': 'mp3',
    'audio/mp3': 'mp3',
    'audio/wav': 'wav',
    'audio/x-wav': 'wav',
    'audio/wave': 'wav'
  };

  // =========================================================================
  // Document Management
  // =========================================================================

  async loadModelSettings(): Promise<void> {
    try {
      const settings = await this.apiService.getModelSettings();
      this.currentProvider.set(settings.active_provider as 'local' | 'azure');
      this.currentModelName.set(settings.model_name || '');
    } catch (error) {
      console.error('Failed to load model settings:', error);
    }
  }

  async toggleProvider(): Promise<void> {
    if (this.isSwitchingProvider()) return;
    const next = this.currentProvider() === 'azure' ? 'local' : 'azure';
    this.isSwitchingProvider.set(true);
    try {
      const result = await this.apiService.switchProvider(next);
      this.currentProvider.set(result.active_provider as 'local' | 'azure');
      this.currentModelName.set(result.model_name || '');
    } catch (error: any) {
      this.uploadError.set(error?.error?.detail || 'Failed to switch provider');
    } finally {
      this.isSwitchingProvider.set(false);
    }
  }

  async loadDocuments(): Promise<void> {
    try {
      this.loadingDocuments.set(true);
      const response = await this.apiService.getDocuments();
      this.availableDocuments.set(response.documents || []);
    } catch (error) {
      console.error('Error loading documents:', error);
      this.uploadError.set('Failed to load documents');
    } finally {
      this.loadingDocuments.set(false);
    }
  }

  onFilesSelected(event: Event): void {
    const input = event.target as HTMLInputElement;
    const newFiles = Array.from(input.files || []);
    if (newFiles.length === 0) return;

    const allowedExtensions = ['pdf', 'png', 'jpg', 'jpeg', 'mp3', 'wav'];
    for (const file of newFiles) {
      const ext = file.name.split('.').pop()?.toLowerCase();
      const mimeValid = this.allowedMimeTypes[file.type];
      const extValid = ext && allowedExtensions.includes(ext);
      if (!mimeValid && !extValid) {
        this.uploadError.set(`Invalid file type: ${file.name} (type: ${file.type})`);
        input.value = '';
        return;
      }
    }

    const currentFiles = this.filesToUpload();
    const existingNames = new Set(currentFiles.map(f => f.name));
    const filesToAdd = newFiles.filter(f => !existingNames.has(f.name));
    this.filesToUpload.set([...currentFiles, ...filesToAdd]);
    this.uploadError.set(null);
    input.value = '';
  }

  removeFile(index: number): void {
    this.filesToUpload.set(this.filesToUpload().filter((_, i) => i !== index));
  }

  clearFiles(): void {
    this.filesToUpload.set([]);
  }

  toggleDocumentSelection(filename: string): void {
    const current = this.selectedDocuments();
    if (current.includes(filename)) {
      this.selectedDocuments.set(current.filter(f => f !== filename));
    } else {
      this.selectedDocuments.set([...current, filename]);
    }
  }

  isDocumentSelected(filename: string): boolean {
    return this.selectedDocuments().includes(filename);
  }

  onSearchAllChange(): void {
    if (this.searchAllDocs) this.selectedDocuments.set([]);
  }

  getHeaderStatus(): string {
    if (this.searchAllDocs) return ' Searching all documents';
    if (this.selectedDocuments().length > 0) return ` Querying ${this.selectedDocuments().length} selected document(s)`;
    if (this.uploadedInSession().length > 0) return ` Session context: ${this.uploadedInSession().length} document(s)`;
    if (this.availableDocuments().length > 0) return ' Select documents or ask about all';
    return ' Upload documents to get started';
  }

  getFileIcon(filename: string): string {
    const ext = filename.split('.').pop()?.toLowerCase();
    if (ext === 'pdf') return '📄';
    if (['jpg', 'jpeg', 'png'].includes(ext || '')) return '🖼️';
    if (['mp3', 'wav'].includes(ext || '')) return '🎵';
    return '📄';
  }

  // =========================================================================
  // Query Handling — now with SSE streaming
  // =========================================================================

  async handleQuery(question: string): Promise<void> {
    if (!question?.trim()) {
      this.uploadError.set('Please enter a question.');
      return;
    }

    this.isLoading.set(true);
    this.uploadError.set(null);

    // Reset progress
    this.analysisPhase.set('classification');
    this.analysisMessage.set('Starting analysis...');
    this.analysisPercent.set(0);
    this.analysisSteps.set([]);

    this.appendMessage({ sender: 'user', text: question });
    this.scrollToBottom();

    try {
      let newlyUploadedFiles: string[] = [];

      // Step 1: Upload new files if any
      if (this.filesToUpload().length > 0) {
        this.analysisMessage.set('Uploading documents...');
        const uploadResponse = await this.apiService.uploadFiles(this.filesToUpload());
        if (uploadResponse?.filenames) {
          newlyUploadedFiles = uploadResponse.filenames;
          this.uploadedInSession.set([...this.uploadedInSession(), ...newlyUploadedFiles]);
          await this.loadDocuments();
        }
        this.clearFiles();
      }

      // Step 2: Determine search scope
      let searchFilenames: string[] = [];
      let useAllDocs = this.searchAllDocs;

      if (this.selectedDocuments().length > 0) {
        searchFilenames = this.selectedDocuments();
        useAllDocs = false;
      } else if (newlyUploadedFiles.length > 0) {
        searchFilenames = newlyUploadedFiles;
        useAllDocs = false;
      } else if (!this.searchAllDocs && this.uploadedInSession().length > 0) {
        searchFilenames = this.uploadedInSession();
        useAllDocs = false;
      }

      // Step 3: Stream the query
      this.apiService.queryDocumentStream(
        question,
        searchFilenames,
        newlyUploadedFiles,
        useAllDocs,
        undefined,
        this.authCookie
      ).subscribe({
        next: (event: StreamEvent) => {
          switch (event.type) {
            case 'progress':
              this.handleProgress(event.data);
              this.scrollToBottom();
              break;

            case 'result':
              this.isLoading.set(false);
              const answer = event.data.answer || event.data.report || 'No answer received';
              this.appendMessage({
                sender: 'agent',
                text: answer,
                reportSections: event.data.report_sections,
                metadata: {
                  filesSearched: event.data.files_searched,
                  filesProcessed: event.data.files_processed,
                  searchScope: event.data.search_scope,
                  conversationMessages: event.data.conversation_messages,
                  teamPersistent: event.data.team_persistent
                }
              });
              this.scrollToBottom();
              break;

            case 'error':
              this.isLoading.set(false);
              this.appendMessage({
                sender: 'agent',
                text: `Error during analysis: ${event.data.message}`
              });
              break;
          }
        },
        error: (err) => {
          console.error('Stream error:', err);
          this.isLoading.set(false);

          // Fallback to non-streaming endpoint
          this.fallbackQuery(question, searchFilenames, newlyUploadedFiles, useAllDocs);
        },
        complete: () => {
          // If still loading (no result event received), mark done
          if (this.isLoading()) {
            this.isLoading.set(false);
          }
        }
      });

    } catch (err: any) {
      console.error('Error:', err);
      this.isLoading.set(false);
      const errorMessage = err?.error?.detail || err?.message || 'Unknown error';
      this.uploadError.set(errorMessage);
      this.appendMessage({ sender: 'agent', text: ` Error: ${errorMessage}` });
    }
  }

  /**
   * Fallback: if /query/stream is not available, use original endpoint.
   * This way the app still works even before the backend is updated.
   */
  private async fallbackQuery(
    question: string,
    filenames: string[],
    uploaded: string[],
    useAllDocs: boolean
  ): Promise<void> {
    try {
      this.analysisMessage.set('Streaming unavailable, using standard query...');
      this.analysisPercent.set(50);

      const queryResponse = await this.apiService.queryDocument(
        question, filenames, uploaded, useAllDocs, undefined, this.authCookie
      );

      this.isLoading.set(false);
      const answer = queryResponse?.answer ?? 'No answer received';
      this.appendMessage({
        sender: 'agent',
        text: answer,
        reportSections: queryResponse.report_sections,
        metadata: {
          filesSearched: queryResponse.files_searched,
          filesProcessed: queryResponse.files_processed,
          searchScope: queryResponse.search_scope,
          conversationMessages: queryResponse.conversation_messages,
          teamPersistent: queryResponse.team_persistent
        }
      });
    } catch (fallbackErr: any) {
      this.isLoading.set(false);
      const errorMessage = fallbackErr?.error?.detail || fallbackErr?.message || 'Unknown error';
      this.uploadError.set(errorMessage);
      this.appendMessage({ sender: 'agent', text: ` Error: ${errorMessage}` });
    }
  }

  // =========================================================================
  // Progress Handling
  // =========================================================================

  private handleProgress(progress: ProgressEvent): void {
    this.analysisPhase.set(progress.phase);
    this.analysisPercent.set(progress.percent);
    this.analysisMessage.set(progress.message);

    // Build step timeline (keep last 6)
    const steps = this.analysisSteps();
    const lastStep = steps[steps.length - 1];
    if (progress.message !== lastStep) {
      const updated = [...steps, progress.message];
      this.analysisSteps.set(updated.length > 6 ? updated.slice(-6) : updated);
    }
  }



  getPhaseName(phase: string): string {
    const names: Record<string, string> = {
      'classification': 'Analyzing Query',
      'knowledge_gathering': 'Gathering Intelligence',
      'active_scanning': 'Scanning Application',
      'report_generation': 'Generating Report'
    };
    return names[phase] || 'Processing...';
  }

  // =========================================================================
  // Chat Utilities
  // =========================================================================

  onKeyPress(event: KeyboardEvent, value: string): void {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      this.handleQuery(value);
      if (this.promptInputRef?.nativeElement) {
        this.promptInputRef.nativeElement.value = '';
      }
    }
  }

  async clearChat(): Promise<void> {
    try {
      await this.apiService.clearSession();
      this.chatMessages.set([{
        sender: 'agent',
        text: 'Chat cleared! Session reset. Ask me anything!'
      }]);
      this.uploadedInSession.set([]);
      this.selectedDocuments.set([]);
      this.searchAllDocs = false;
    } catch (error) {
      console.error('Clear error:', error);
    }
  }

  private appendMessage(message: ChatMessage): void {
    // If agent message has no backend sections (or empty array), try parsing from raw text
    if (message.sender === 'agent' && (!message.reportSections || message.reportSections.length === 0)) {
      const parsed = this.parseReportText(message.text);
      if (parsed.length > 1) {
        message.reportSections = parsed;
      }
    }
    this.chatMessages.update(messages => [...messages, message]);
  }

  // Parse a security report text into sections using header markers.
  // Sections are joined with "\n\n" and each starts with " N. TITLE"
  private parseReportText(text: string): ReportSection[] {
    // Split on the double-newline separator between sections
    const parts = text.split(/\n\n(?= \d)/);
    const sections: ReportSection[] = [];

    for (const part of parts) {
      // Match " 1. TITLE" or " 3b. TITLE" at start of part
      const headerMatch = part.match(/^ ?(\d+[a-z]?)\. ([^\n]+)/);
      if (headerMatch) {
        const id      = headerMatch[1];
        const title   = `${id}. ${headerMatch[2].trim()}`;
        const content = part.slice(headerMatch[0].length).trim();
        sections.push({ id, title, content });
      }
    }
    return sections;
  }

  private scrollToBottom(): void {
    setTimeout(() => {
      const el = this.scrollContainerRef?.nativeElement;
      if (el) el.scrollTop = el.scrollHeight;
    }, 50);
  }
}

bootstrapApplication(AppComponent, appConfig);