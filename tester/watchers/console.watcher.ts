import { Page } from 'playwright';

export type ConsoleLevel = 'warning' | 'error';

export type ConsoleEvent = {
  timestamp: string;
  role: string;
  flow: string;
  level: ConsoleLevel;
  message: string;
};

export type ConsoleWatcher = {
  setContext: (role: string, flow: string) => void;
  getLogs: () => ConsoleEvent[];
};

/** Attaches browser console watcher and collects warnings/errors per context. */
export function attachConsoleWatcher(page: Page): ConsoleWatcher {
  let role = 'global';
  let flow = 'bootstrap';
  const logs: ConsoleEvent[] = [];

  page.on('console', (msg) => {
    const type = msg.type();
    if (type !== 'warning' && type !== 'error') return;
    logs.push({
      timestamp: new Date().toISOString(),
      role,
      flow,
      level: type,
      message: msg.text()
    });
  });

  return {
    setContext: (nextRole: string, nextFlow: string) => {
      role = nextRole;
      flow = nextFlow;
    },
    getLogs: () => [...logs]
  };
}
