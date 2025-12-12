import React, { useState } from 'react';
import axios from 'axios';
import { jwtDecode } from 'jwt-decode';

const API = '/api';

function App() {
  const [token, setToken] = useState('');
  const [response, setResponse] = useState(null);
  const [username, setUsername] = useState('testuser');
  const [password, setPassword] = useState('password123');

  const login = async (endpoint) => {
    try {
      const res = await axios.post(`${API}${endpoint}`, { username, password });
      setToken(res.data.data?.token || '');
      setResponse(res.data);
    } catch (err) {
      setResponse(err.response?.data || { error: err.message });
    }
  };

  const testEndpoint = async (endpoint, method = 'GET') => {
    try {
      const config = { headers: { Authorization: `Bearer ${token}` } };
      const res = method === 'GET' 
        ? await axios.get(`${API}${endpoint}`, config)
        : await axios.post(`${API}${endpoint}`, {}, config);
      setResponse(res.data);
    } catch (err) {
      setResponse(err.response?.data || { error: err.message });
    }
  };

  const decodeToken = () => {
    try {
      const decoded = jwtDecode(token);
      setResponse({ decoded, raw: token });
    } catch (err) {
      setResponse({ error: 'Invalid token' });
    }
  };

  return (
    <div style={{ padding: '20px', fontFamily: 'monospace', maxWidth: '1200px', margin: '0 auto' }}>
      <h1>🔐 JWT Attack & Defense Playground</h1>
      
      <section style={{ marginBottom: '20px', padding: '15px', background: '#f5f5f5', borderRadius: '8px' }}>
        <h2>Authentication</h2>
        <input placeholder="Username" value={username} onChange={e => setUsername(e.target.value)} style={{ marginRight: '10px', padding: '8px' }} />
        <input placeholder="Password" value={password} onChange={e => setPassword(e.target.value)} style={{ marginRight: '10px', padding: '8px' }} />
        <button onClick={() => login('/login/vulnerable')} style={{ marginRight: '10px', padding: '8px 16px' }}>Login (Vulnerable)</button>
        <button onClick={() => login('/login/secure')} style={{ padding: '8px 16px' }}>Login (Secure)</button>
      </section>

      <section style={{ marginBottom: '20px', padding: '15px', background: '#ffe0e0', borderRadius: '8px' }}>
        <h2>⚠️ Vulnerable Endpoints</h2>
        <button onClick={() => testEndpoint('/vulnerable/none-algorithm')} style={{ marginRight: '10px', padding: '8px 16px' }}>None Algorithm</button>
        <button onClick={() => testEndpoint('/vulnerable/algorithm-confusion')} style={{ marginRight: '10px', padding: '8px 16px' }}>Algorithm Confusion</button>
        <button onClick={() => testEndpoint('/vulnerable/no-expiry')} style={{ padding: '8px 16px' }}>No Expiry Check</button>
      </section>

      <section style={{ marginBottom: '20px', padding: '15px', background: '#e0ffe0', borderRadius: '8px' }}>
        <h2>✅ Secure Endpoints</h2>
        <button onClick={() => testEndpoint('/secure/protected')} style={{ marginRight: '10px', padding: '8px 16px' }}>Protected Resource</button>
        <button onClick={() => testEndpoint('/secure/refresh', 'POST')} style={{ marginRight: '10px', padding: '8px 16px' }}>Refresh Token</button>
        <button onClick={() => testEndpoint('/secure/logout', 'POST')} style={{ padding: '8px 16px' }}>Logout</button>
      </section>

      <section style={{ marginBottom: '20px', padding: '15px', background: '#e0e0ff', borderRadius: '8px' }}>
        <h2>🔧 Tools</h2>
        <button onClick={decodeToken} style={{ padding: '8px 16px' }}>Decode Token</button>
      </section>

      <section style={{ marginBottom: '20px' }}>
        <h3>Current Token:</h3>
        <textarea value={token} onChange={e => setToken(e.target.value)} style={{ width: '100%', height: '80px', fontFamily: 'monospace', fontSize: '12px' }} />
      </section>

      <section>
        <h3>Response:</h3>
        <pre style={{ background: '#1e1e1e', color: '#0f0', padding: '15px', borderRadius: '8px', overflow: 'auto' }}>
          {JSON.stringify(response, null, 2)}
        </pre>
      </section>
    </div>
  );
}

export default App;
