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
  conversation_messages?: number;
  team_persistent?: boolean;
}

interface StreamError {
  message: string;
  phase?: string;
}

type StreamEvent =
  | { type: 'progress'; data: ProgressEvent }
  | { type: 'result'; data: StreamResult }
  | { type: 'error'; data: StreamError };

// =============================================================================
// API Service
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
      console.log('Session ID:', this.sessionId);
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

  queryDocument(
    question: string,
    sessionId?: string,
    authCookie: string = ''
  ): Promise<any> {
    const payload: any = {
      question,
      session_id: sessionId || this.getSessionId()
    };
    if (authCookie) payload.auth_cookie = authCookie;
    return firstValueFrom(
      this.http.post<any>('/api/query/', payload, {
        headers: { 'Content-Type': 'application/json' }
      })
    );
  }

  queryDocumentStream(
    question: string,
    sessionId?: string,
    authCookie: string = ''
  ): Observable<StreamEvent> {
    const subject = new Subject<StreamEvent>();
    const payload: any = {
      question,
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
    const controller = new AbortController();
    // If no SSE bytes arrive at all, fail fast so the UI can fall back.
    const connectTimer = setTimeout(() => controller.abort(), 20000);

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'text/event-stream'
        },
        body: JSON.stringify(body),
        signal: controller.signal
      });

      if (!response.ok) {
        clearTimeout(connectTimer);
        this.ngZone.run(() =>
          subject.error(new Error(`HTTP ${response.status}: ${response.statusText}`))
        );
        return;
      }

      const contentType = response.headers.get('content-type') || '';
      if (!contentType.includes('text/event-stream') && !contentType.includes('text/plain')) {
        // Likely HTML from a misconfigured proxy — do not hang parsing.
        clearTimeout(connectTimer);
        this.ngZone.run(() =>
          subject.error(new Error('Streaming endpoint unavailable (unexpected response type)'))
        );
        return;
      }

      const reader = response.body!.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      let gotEvent = false;

      while (true) {
        const { done, value } = await reader.read();

        if (done) {
          clearTimeout(connectTimer);
          if (buffer.trim()) this.parseSSE(buffer, subject);
          if (!gotEvent) {
            this.ngZone.run(() =>
              subject.error(new Error('Stream closed without events'))
            );
          } else {
            this.ngZone.run(() => subject.complete());
          }
          break;
        }

        buffer += decoder.decode(value, { stream: true });
        const messages = buffer.split('\n\n');
        buffer = messages.pop() || '';

        for (const msg of messages) {
          if (msg.trim()) {
            gotEvent = true;
            clearTimeout(connectTimer);
            this.parseSSE(msg, subject);
          }
        }
      }
    } catch (err) {
      clearTimeout(connectTimer);
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
  <div class="h-screen bg-gray-900 text-white flex flex-col">
    <!-- Header -->
    <div class="bg-gray-800 border-b border-gray-700 px-4 py-3 flex justify-between items-center shrink-0">
      <div>
        <h1 class="text-xl font-bold text-white">Multi-Agent Threat Modeling System</h1>
        <p class="text-sm text-gray-400 mt-0.5">{{ getHeaderStatus() }}</p>
      </div>
      <div class="flex items-center gap-3">
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

    <!-- Messages (same width column as prompt) -->
    <div #scrollContainer class="flex-1 overflow-y-auto">
      <div class="max-w-4xl mx-auto px-4 py-6 space-y-4">
        <div *ngIf="chatMessages().length === 1" class="text-center py-10">
          <h3 class="text-lg font-semibold text-gray-300 mb-2">Welcome to Multi-Agent Threat Modeling System</h3>
          <p class="text-sm text-gray-500 max-w-xl mx-auto">
            Ask a security question or paste a URL to scan a web application.
          </p>
        </div>

        <div *ngFor="let msg of chatMessages(); let msgIdx = index"
             class="flex w-full"
             [ngClass]="{ 'justify-end': msg.sender === 'user', 'justify-start': msg.sender === 'agent' }">
          <div class="rounded-lg p-4"
               [ngClass]="{
                 'bg-blue-700 max-w-[85%]': msg.sender === 'user',
                 'bg-gray-800 border border-gray-700 w-full': msg.sender === 'agent'
               }">
            <div *ngIf="msg.sender === 'user'" class="whitespace-pre-wrap text-sm">{{ msg.text }}</div>

            <div *ngIf="msg.sender === 'agent'">
              <ng-container *ngIf="msg.reportSections && msg.reportSections.length > 1; else plainText">
                <div class="space-y-2">
                  <div *ngFor="let section of msg.reportSections"
                       class="border border-gray-700 rounded-lg overflow-hidden">
                    <button type="button"
                            (click)="toggleSection(msgIdx, section.id)"
                            class="w-full flex items-center justify-between px-4 py-3 text-left hover:bg-gray-700 transition-colors">
                      <span class="text-sm font-semibold text-gray-200">{{ section.title }}</span>
                      <span class="text-gray-400 text-xs">{{ getActiveSection(msgIdx) === section.id ? '▾' : '▸' }}</span>
                    </button>
                    <div *ngIf="getActiveSection(msgIdx) === section.id"
                         class="px-4 py-3 text-sm text-gray-300 whitespace-pre-wrap border-t border-gray-700">
                      {{ section.content }}
                    </div>
                  </div>
                </div>
              </ng-container>
              <ng-template #plainText>
                <div class="whitespace-pre-wrap text-sm text-gray-200">{{ msg.text }}</div>
              </ng-template>
            </div>
          </div>
        </div>

        <!-- Loading / progress -->
        <div *ngIf="isLoading()" class="flex justify-start w-full">
          <div class="bg-gray-800 border border-gray-700 rounded-lg p-4 w-full">
            <div class="flex items-center gap-3 mb-3">
              <div class="animate-spin h-5 w-5 border-2 border-blue-400 border-t-transparent rounded-full"></div>
              <div>
                <p class="text-sm font-medium text-white">{{ getPhaseName(analysisPhase()) }}</p>
                <p class="text-xs text-gray-400">{{ analysisMessage() }}</p>
              </div>
            </div>
            <div class="w-full bg-gray-700 rounded-full h-2 mb-2">
              <div class="bg-blue-500 h-2 rounded-full transition-all duration-300"
                   [style.width.%]="analysisPercent()"></div>
            </div>
            <ul *ngIf="analysisSteps().length" class="mt-2 space-y-1">
              <li *ngFor="let step of analysisSteps()" class="text-xs text-gray-500">• {{ step }}</li>
            </ul>
          </div>
        </div>
      </div>
    </div>

    <!-- Prompt (aligned with message column) -->
    <div class="border-t border-gray-700 bg-gray-800 shrink-0">
      <div class="max-w-4xl mx-auto px-4 py-4 space-y-3">
        <div *ngIf="uploadError()" class="text-red-300 bg-red-900/60 border border-red-700 p-3 rounded-lg text-sm">
          {{ uploadError() }}
        </div>

        <textarea #promptInput
                  rows="3"
                  placeholder="Ask a security question or paste a URL to scan..."
                  (keydown)="onKeyPress($event, promptInput.value)"
                  [disabled]="isLoading()"
                  class="w-full px-4 py-3 rounded-lg bg-gray-900 border border-gray-600 text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none resize-none text-sm disabled:opacity-60"></textarea>

        <div class="flex items-center gap-3">
          <button type="button" (click)="showAuthInput = !showAuthInput"
                  class="text-xs text-yellow-400 hover:text-yellow-300">
            {{ showAuthInput || authCookie ? 'Session cookie' : 'Add session cookie (optional)' }}
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
          {{ isLoading() ? 'Analyzing...' : 'Submit Query' }}
        </button>
      </div>
    </div>
  </div>
  `,
  styles: [`
    :host { display: block; height: 100%; }
  `],
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class AppComponent {
  constructor(private apiService: ApiService) {
    this.loadModelSettings();
  }

  @ViewChild('promptInput') promptInputRef?: ElementRef<HTMLTextAreaElement>;
  @ViewChild('scrollContainer') scrollContainerRef?: ElementRef<HTMLDivElement>;

  chatMessages = signal<ChatMessage[]>([{
    sender: 'agent',
    text: 'Hello! Ask a security question or paste a URL to scan a web application.'
  }]);
  uploadError = signal<string | null>(null);
  isLoading = signal(false);

  currentProvider = signal<'local' | 'azure'>('azure');
  currentModelName = signal<string>('');
  isSwitchingProvider = signal(false);

  analysisPhase = signal<string>('');
  analysisMessage = signal<string>('');
  analysisPercent = signal<number>(0);
  analysisSteps = signal<string[]>([]);

  authCookie = '';
  showAuthInput = false;

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

  async loadModelSettings(): Promise<void> {
    try {
      const settings = await this.apiService.getModelSettings();
      this.currentProvider.set(settings.active_provider as 'local' | 'azure');
      this.currentModelName.set(settings.model_name || '');
    } catch (error) {
      console.error('Failed to load model settings:', error);
      this.uploadError.set(
        'Cannot reach backend API. Start the FastAPI server on port 8000 and restart ng serve.'
      );
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

  getHeaderStatus(): string {
    const model = this.currentModelName();
    return model ? `Web and AI scanning · ${model}` : 'Web and AI scanning';
  }

  async handleQuery(question: string): Promise<void> {
    if (!question?.trim() || this.isLoading()) {
      if (!question?.trim()) this.uploadError.set('Please enter a question.');
      return;
    }

    this.isLoading.set(true);
    this.uploadError.set(null);
    this.analysisPhase.set('classification');
    this.analysisMessage.set('Starting analysis...');
    this.analysisPercent.set(5);
    this.analysisSteps.set([]);

    this.appendMessage({ sender: 'user', text: question });
    this.scrollToBottom();

    let settled = false;
    const finish = () => {
      if (!settled) {
        settled = true;
        this.isLoading.set(false);
      }
    };

    try {
      this.apiService.queryDocumentStream(
        question,
        undefined,
        this.authCookie
      ).subscribe({
        next: (event: StreamEvent) => {
          switch (event.type) {
            case 'progress':
              this.handleProgress(event.data);
              this.scrollToBottom();
              break;

            case 'result': {
              finish();
              const answer = event.data.answer || event.data.report || 'No answer received';
              this.appendMessage({
                sender: 'agent',
                text: answer,
                reportSections: event.data.report_sections,
                metadata: {
                  conversationMessages: event.data.conversation_messages,
                  teamPersistent: event.data.team_persistent
                }
              });
              this.scrollToBottom();
              break;
            }

            case 'error':
              finish();
              this.appendMessage({
                sender: 'agent',
                text: `Error during analysis: ${event.data.message}`
              });
              this.scrollToBottom();
              break;
          }
        },
        error: async (err) => {
          console.error('Stream error:', err);
          this.analysisMessage.set('Streaming unavailable, using standard query...');
          this.analysisPercent.set(40);
          await this.fallbackQuery(question);
          finish();
        },
        complete: () => {
          // If stream ended without a result/error event, fall back.
          if (!settled && this.isLoading()) {
            this.analysisMessage.set('Completing via standard query...');
            this.fallbackQuery(question).finally(finish);
          }
        }
      });
    } catch (err: any) {
      console.error('Error:', err);
      await this.fallbackQuery(question);
      finish();
    }
  }

  private async fallbackQuery(question: string): Promise<void> {
    try {
      this.analysisMessage.set('Waiting for response...');
      this.analysisPercent.set(60);

      const queryResponse = await this.apiService.queryDocument(
        question, undefined, this.authCookie
      );

      const answer = queryResponse?.answer ?? 'No answer received';
      this.appendMessage({
        sender: 'agent',
        text: answer,
        reportSections: queryResponse.report_sections,
        metadata: {
          conversationMessages: queryResponse.conversation_messages,
          teamPersistent: queryResponse.team_persistent
        }
      });
      this.scrollToBottom();
    } catch (fallbackErr: any) {
      const errorMessage =
        fallbackErr?.error?.detail ||
        fallbackErr?.message ||
        'Backend unreachable. Ensure FastAPI is running on port 8000.';
      const detail = typeof errorMessage === 'string'
        ? errorMessage
        : JSON.stringify(errorMessage);
      this.uploadError.set(detail);
      this.appendMessage({ sender: 'agent', text: `Error: ${detail}` });
      this.scrollToBottom();
    }
  }

  private handleProgress(progress: ProgressEvent): void {
    this.analysisPhase.set(progress.phase);
    this.analysisPercent.set(progress.percent);
    this.analysisMessage.set(progress.message);

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

  onKeyPress(event: KeyboardEvent, value: string): void {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      if (this.isLoading()) return;
      this.handleQuery(value);
      if (this.promptInputRef?.nativeElement) {
        this.promptInputRef.nativeElement.value = '';
      }
    }
  }

  async clearChat(): Promise<void> {
    this.isLoading.set(false);
    this.uploadError.set(null);
    this.analysisSteps.set([]);
    try {
      await this.apiService.clearSession();
    } catch (error) {
      console.error('Clear error:', error);
    }
    this.chatMessages.set([{
      sender: 'agent',
      text: 'Chat cleared! Session reset. Ask me anything!'
    }]);
  }

  private appendMessage(message: ChatMessage): void {
    if (message.sender === 'agent' && (!message.reportSections || message.reportSections.length === 0)) {
      const parsed = this.parseReportText(message.text);
      if (parsed.length > 1) {
        message.reportSections = parsed;
      }
    }
    this.chatMessages.update(messages => [...messages, message]);
  }

  private parseReportText(text: string): ReportSection[] {
    const parts = text.split(/\n\n(?= \d)/);
    const sections: ReportSection[] = [];

    for (const part of parts) {
      const headerMatch = part.match(/^ ?(\d+[a-z]?)\. ([^\n]+)/);
      if (headerMatch) {
        const id = headerMatch[1];
        const title = `${id}. ${headerMatch[2].trim()}`;
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
