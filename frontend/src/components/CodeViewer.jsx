import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';

export const CodeViewer = ({ code, language = 'json', title, maxHeight = '260px' }) => {
  const [copied, setCopied] = useState(false);

  const formattedCode =
    typeof code === 'object' ? JSON.stringify(code, null, 2) : String(code || '');

  const handleCopy = () => {
    navigator.clipboard.writeText(formattedCode);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div
      style={{
        background: '#f8fafc',
        border: '1px solid var(--border-subtle)',
        borderRadius: 'var(--radius-md)',
        overflow: 'hidden',
        fontSize: '0.8125rem',
      }}
    >
      {title && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '8px 14px',
            background: '#f1f5f9',
            borderBottom: '1px solid var(--border-subtle)',
            color: 'var(--text-secondary)',
            fontWeight: 600,
            fontSize: '0.75rem',
          }}
        >
          <span>{title}</span>
          <button
            onClick={handleCopy}
            className="btn btn-ghost btn-sm"
            style={{ padding: '2px 8px', height: '24px' }}
            title="Copy to clipboard"
          >
            {copied ? (
              <span style={{ color: 'var(--emerald)', display: 'flex', alignItems: 'center', gap: 4 }}>
                <Check size={12} /> Copied
              </span>
            ) : (
              <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <Copy size={12} /> Copy
              </span>
            )}
          </button>
        </div>
      )}
      <pre
        className="mono"
        style={{
          padding: '14px',
          margin: 0,
          color: '#0284c7',
          maxHeight,
          overflowY: 'auto',
          lineHeight: 1.5,
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-all',
        }}
      >
        <code>{formattedCode}</code>
      </pre>
    </div>
  );
};
