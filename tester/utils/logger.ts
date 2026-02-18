export type Severity = 'PASS' | 'INFO' | 'WARN' | 'FAIL' | 'CRITICAL';

export type LogEntry = {
  timestamp: string;
  severity: Severity;
  role: string;
  flow: string;
  step: string;
  message: string;
};

/** Structured logger for role-aware autonomous test execution. */
export class Logger {
  private readonly entries: LogEntry[] = [];

  /** Appends a log entry and prints it to stdout. */
  public log(severity: Severity, role: string, flow: string, step: string, message: string): void {
    const entry: LogEntry = { timestamp: new Date().toISOString(), severity, role, flow, step, message };
    this.entries.push(entry);
    console.log(`[${entry.timestamp}] [${severity}] [${role}] [${flow}] [${step}] ${message}`);
  }

  /** Convenience helper for non-error progress logs. */
  public info(role: string, flow: string, step: string, message: string): void {
    this.log('INFO', role, flow, step, message);
  }

  /** Convenience helper for degraded but non-fatal behavior. */
  public warn(role: string, flow: string, step: string, message: string): void {
    this.log('WARN', role, flow, step, message);
  }

  /** Convenience helper for functional test failures. */
  public fail(role: string, flow: string, step: string, message: string): void {
    this.log('FAIL', role, flow, step, message);
  }

  /** Convenience helper for security boundary failures. */
  public critical(role: string, flow: string, step: string, message: string): void {
    this.log('CRITICAL', role, flow, step, message);
  }

  /** Returns a copy of all structured log entries. */
  public getEntries(): LogEntry[] {
    return [...this.entries];
  }
}
