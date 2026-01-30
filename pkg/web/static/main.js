// Termshark Web UI - Main JavaScript

// HTML escape utility to prevent XSS
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Debug logging - visible on page when errors occur or via console: showDebugLog()
const MAX_DEBUG_LINES = 500;
let debugLineCount = 0;
function debugLog(msg) {
    console.log('[termshark]', msg);
    const el = document.getElementById('debug-log');
    if (el) {
        debugLineCount++;
        if (debugLineCount > MAX_DEBUG_LINES) {
            // Trim oldest half of lines
            const lines = el.textContent.split('\n');
            el.textContent = lines.slice(Math.floor(lines.length / 2)).join('\n');
            debugLineCount = Math.floor(debugLineCount / 2);
        }
        el.textContent += new Date().toISOString().slice(11, 23) + ' ' + msg + '\n';
        el.scrollTop = el.scrollHeight;
        // Show log panel on errors
        if (msg.includes('ERROR') || msg.includes('FAILED')) {
            el.style.display = 'block';
        }
    }
}
// Allow manually showing debug log from console
window.showDebugLog = function() {
    const el = document.getElementById('debug-log');
    if (el) el.style.display = 'block';
};

class SharkdClient {
    constructor() {
        this.ws = null;
        this.requestId = 0;
        this.pendingRequests = new Map();
        this.onStatusChange = null;
        this.supportsRegistry = false;
        this.eventHandlers = new Map(); // For push notifications
    }

    connect() {
        // Prevent reconnect stacking
        if (this._reconnectTimer) {
            clearTimeout(this._reconnectTimer);
            this._reconnectTimer = null;
        }
        // Close existing connection if any
        if (this.ws) {
            this.ws.onclose = null;
            this.ws.onerror = null;
            try { this.ws.close(); } catch (e) { /* ignore */ }
        }

        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws`;

        this.ws = new WebSocket(wsUrl);

        this.ws.onopen = () => {
            console.log('WebSocket connected');
            if (this.onStatusChange) {
                this.onStatusChange('connected', 'Connected');
            }
        };

        this.ws.onclose = () => {
            console.log('WebSocket disconnected');
            // Reject all pending requests
            for (const [id, pending] of this.pendingRequests) {
                pending.reject(new Error('WebSocket disconnected'));
            }
            this.pendingRequests.clear();

            if (this.onStatusChange) {
                this.onStatusChange('error', 'Disconnected');
            }
            // Attempt reconnect after 3 seconds
            this._reconnectTimer = setTimeout(() => this.connect(), 3000);
        };

        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            if (this.onStatusChange) {
                this.onStatusChange('error', 'Connection error');
            }
        };

        this.ws.onmessage = (event) => {
            let response;
            try {
                response = JSON.parse(event.data);
            } catch (e) {
                console.error('Failed to parse WebSocket message:', e);
                return;
            }

            // Check if this is a push notification (no id field)
            if (response.method && !response.id) {
                const handler = this.eventHandlers.get(response.method);
                if (handler) {
                    handler(response.params);
                }
                return;
            }

            // Regular RPC response
            const pending = this.pendingRequests.get(response.id);
            if (pending) {
                this.pendingRequests.delete(response.id);
                if (response.error) {
                    pending.reject(new Error(response.error.message));
                } else {
                    pending.resolve(response.result);
                }
            }
        };
    }

    // Subscribe to push notifications
    async subscribe(event, handler) {
        this.eventHandlers.set(event, handler);
        return this.call('subscribe', { event: event });
    }

    // Unsubscribe from push notifications
    async unsubscribe(event) {
        this.eventHandlers.delete(event);
        return this.call('unsubscribe', { event: event });
    }

    async call(method, params = {}) {
        if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
            throw new Error('WebSocket not connected');
        }

        const id = ++this.requestId;
        const request = {
            jsonrpc: '2.0',
            id: id,
            method: method,
            params: params
        };

        return new Promise((resolve, reject) => {
            this.pendingRequests.set(id, { resolve, reject });
            this.ws.send(JSON.stringify(request));

            // Timeout after 30 seconds
            setTimeout(() => {
                if (this.pendingRequests.has(id)) {
                    this.pendingRequests.delete(id);
                    reject(new Error('Request timeout'));
                }
            }, 30000);
        });
    }

    // Session management methods
    async listSessions() {
        return this.call('sessions.list');
    }

    async createSession(name) {
        return this.call('sessions.create', { name: name });
    }

    async joinSession(sessionId) {
        return this.call('sessions.join', { id: sessionId });
    }

    async leaveSession() {
        return this.call('sessions.leave');
    }

    async getSessionInfo(sessionId = null) {
        const params = sessionId ? { id: sessionId } : {};
        return this.call('sessions.info', params);
    }

    async deleteSession(sessionId) {
        return this.call('sessions.delete', { id: sessionId });
    }

    // Check if server supports session registry
    async checkRegistrySupport() {
        try {
            await this.listSessions();
            this.supportsRegistry = true;
            return true;
        } catch (e) {
            this.supportsRegistry = false;
            return false;
        }
    }

    // Packet analysis methods
    async getStatus() {
        return this.call('status');
    }

    async loadFile(filename) {
        return this.call('load', { file: filename });
    }

    async getFrames(filter = '', skip = 0, limit = 1000) {
        const params = { limit: limit };
        if (filter) params.filter = filter;
        if (skip > 0) params.skip = skip;
        return this.call('frames', params);
    }

    async getFrame(frameNum) {
        return this.call('frame', { frame: frameNum, proto: true, bytes: true });
    }

    async checkFilter(filter) {
        return this.call('check', { filter: filter });
    }

    async followStream(protocol, streamIndex) {
        return this.call('follow', {
            follow: protocol,
            filter: `${protocol}.stream eq ${streamIndex}`
        });
    }

    async getTaps(taps) {
        return this.call('tap', { tap0: taps[0] });
    }

    async getIntervals(interval = 1000) {
        return this.call('intervals', { interval: interval });
    }

    // Capture methods
    async listInterfaces() {
        return this.call('listInterfaces');
    }

    async startCapture(iface, captureFilter = '') {
        const params = { interface: iface };
        if (captureFilter) params.captureFilter = captureFilter;
        return this.call('startCapture', params);
    }

    async stopCapture() {
        return this.call('stopCapture');
    }

    async isCapturing() {
        return this.call('isCapturing');
    }
}

class CaptureControls {
    constructor(client) {
        this.client = client;
        this.container = document.getElementById('capture-controls');
        this.interfaceSelect = document.getElementById('interface-select');
        this.startBtn = document.getElementById('start-capture-btn');
        this.stopBtn = document.getElementById('stop-capture-btn');
        this.statusEl = document.getElementById('capture-status');
        this.isCapturing = false;
        this.onCaptureStateChange = null;
        this.pollInterval = null;

        this.setupEventListeners();
    }

    setupEventListeners() {
        this.startBtn.addEventListener('click', () => this.startCapture());
        this.stopBtn.addEventListener('click', () => this.stopCapture());
    }

    async init() {
        try {
            // Try to list interfaces - this determines if capture is supported
            const interfaces = await this.client.listInterfaces();
            if (interfaces && interfaces.length > 0) {
                this.populateInterfaces(interfaces);
                this.container.classList.remove('hidden');

                // Check if already capturing
                const status = await this.client.isCapturing();
                if (status && status.capturing) {
                    this.setCapturingState(true);
                }
            }
        } catch (e) {
            // Capture not supported or error listing interfaces
            console.log('Capture controls not available:', e.message);
        }
    }

    populateInterfaces(interfaces) {
        // Clear existing options except the placeholder
        while (this.interfaceSelect.options.length > 1) {
            this.interfaceSelect.remove(1);
        }

        // Sort by index
        interfaces.sort((a, b) => a.index - b.index);

        for (const iface of interfaces) {
            const option = document.createElement('option');
            option.value = iface.name;
            option.textContent = iface.name;
            if (iface.aliases && iface.aliases.length > 0) {
                option.textContent += ` (${iface.aliases.join(', ')})`;
            }
            this.interfaceSelect.appendChild(option);
        }
    }

    async startCapture() {
        const iface = this.interfaceSelect.value;
        if (!iface) {
            alert('Please select an interface');
            return;
        }

        try {
            await this.client.startCapture(iface);
            this.setCapturingState(true);
            if (this.onCaptureStateChange) {
                this.onCaptureStateChange(true);
            }
        } catch (e) {
            alert('Failed to start capture: ' + e.message);
        }
    }

    async stopCapture() {
        try {
            await this.client.stopCapture();
            this.setCapturingState(false);
            if (this.onCaptureStateChange) {
                this.onCaptureStateChange(false);
            }
        } catch (e) {
            alert('Failed to stop capture: ' + e.message);
        }
    }

    setCapturingState(capturing) {
        this.isCapturing = capturing;
        if (capturing) {
            this.startBtn.classList.add('hidden');
            this.stopBtn.classList.remove('hidden');
            this.interfaceSelect.disabled = true;
            this.statusEl.textContent = 'Capturing...';
            this.statusEl.classList.remove('hidden');
            this.statusEl.classList.add('capturing');
            this.startPolling();
        } else {
            this.startBtn.classList.remove('hidden');
            this.stopBtn.classList.add('hidden');
            this.interfaceSelect.disabled = false;
            this.statusEl.classList.add('hidden');
            this.statusEl.classList.remove('capturing');
            this.stopPolling();
        }
    }

    startPolling() {
        // Prevent duplicate polling intervals
        this.stopPolling();
        // Poll for capture status every 2 seconds
        this.pollInterval = setInterval(async () => {
            try {
                const status = await this.client.isCapturing();
                if (!status.capturing && this.isCapturing) {
                    // Capture stopped externally
                    this.setCapturingState(false);
                    if (this.onCaptureStateChange) {
                        this.onCaptureStateChange(false);
                    }
                }
            } catch (e) {
                // Ignore poll errors
            }
        }, 2000);
    }

    stopPolling() {
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
            this.pollInterval = null;
        }
    }
}

class SessionPicker {
    constructor(client) {
        this.client = client;
        this.modal = document.getElementById('session-modal');
        this.sessionList = document.getElementById('session-list');
        this.sessionInfo = document.getElementById('session-info');
        this.currentSessionId = null;
        this.onSessionJoined = null;

        this.setupEventListeners();
    }

    setupEventListeners() {
        // Open modal
        document.getElementById('session-btn').addEventListener('click', () => {
            this.show();
        });

        // Close modal
        document.getElementById('modal-close').addEventListener('click', () => {
            this.hide();
        });

        // Close on backdrop click
        this.modal.addEventListener('click', (e) => {
            if (e.target === this.modal) {
                this.hide();
            }
        });

        // Create session
        document.getElementById('create-session-btn').addEventListener('click', () => {
            this.createSession();
        });

        // Create on Enter key
        document.getElementById('new-session-name').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.createSession();
            }
        });
    }

    async show() {
        this.modal.classList.remove('hidden');
        await this.refresh();
    }

    hide() {
        this.modal.classList.add('hidden');
    }

    async refresh() {
        try {
            const sessions = await this.client.listSessions();
            this.renderSessions(sessions);
        } catch (error) {
            console.error('Failed to list sessions:', error);
            this.sessionList.innerHTML = '<div class="empty-state">Failed to load sessions</div>';
        }
    }

    renderSessions(sessions) {
        if (!sessions || sessions.length === 0) {
            this.sessionList.innerHTML = '<div class="empty-state">No sessions available. Create one to get started.</div>';
            return;
        }

        this.sessionList.innerHTML = sessions.map(session => {
            const isActive = session.id === this.currentSessionId;
            const createdAt = new Date(session.createdAt).toLocaleTimeString();
            return `
                <div class="session-item ${isActive ? 'active' : ''}" data-id="${session.id}">
                    <div class="session-item-info">
                        <div class="session-item-name">${this.escapeHtml(session.name)}</div>
                        <div class="session-item-meta">
                            ${session.clientCount} client(s) ·
                            ${session.packetCount || 0} packets ·
                            ${session.isCapturing ? 'Capturing' : (this.escapeHtml(session.source) || 'No source')} ·
                            Created ${createdAt}
                        </div>
                    </div>
                    <div class="session-item-actions">
                        ${isActive ?
                            '<button class="small-btn" disabled>Current</button>' :
                            `<button class="join-btn" data-action="join" data-id="${session.id}">Join</button>`
                        }
                        <button class="delete-btn" data-action="delete" data-id="${session.id}">Delete</button>
                    </div>
                </div>
            `;
        }).join('');

        // Add event listeners
        this.sessionList.querySelectorAll('[data-action="join"]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                this.joinSession(btn.dataset.id);
            });
        });

        this.sessionList.querySelectorAll('[data-action="delete"]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                this.deleteSession(btn.dataset.id);
            });
        });

        // Click on row to join
        this.sessionList.querySelectorAll('.session-item').forEach(item => {
            item.addEventListener('click', () => {
                if (item.dataset.id !== this.currentSessionId) {
                    this.joinSession(item.dataset.id);
                }
            });
        });
    }

    async createSession() {
        const nameInput = document.getElementById('new-session-name');
        const name = nameInput.value.trim() || '';

        try {
            const session = await this.client.createSession(name);
            nameInput.value = '';
            await this.joinSession(session.id);
        } catch (error) {
            console.error('Failed to create session:', error);
            alert('Failed to create session: ' + error.message);
        }
    }

    async joinSession(sessionId) {
        try {
            const session = await this.client.joinSession(sessionId);
            this.currentSessionId = session.id;
            this.updateSessionInfo(session);
            this.hide();
            if (this.onSessionJoined) {
                this.onSessionJoined(session);
            }
        } catch (error) {
            console.error('Failed to join session:', error);
            alert('Failed to join session: ' + error.message);
        }
    }

    async deleteSession(sessionId) {
        if (!confirm('Are you sure you want to delete this session?')) {
            return;
        }

        try {
            await this.client.deleteSession(sessionId);
            if (sessionId === this.currentSessionId) {
                this.currentSessionId = null;
                this.sessionInfo.classList.add('hidden');
            }
            await this.refresh();
        } catch (error) {
            console.error('Failed to delete session:', error);
            alert('Failed to delete session: ' + error.message);
        }
    }

    updateSessionInfo(session) {
        this.sessionInfo.textContent = `Session: ${session.name}`;
        this.sessionInfo.classList.remove('hidden');
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

class PacketListView {
    constructor(tableElement, client) {
        this.table = tableElement;
        this.header = document.getElementById('packet-header');
        this.body = document.getElementById('packet-body');
        this.client = client;
        this.columns = [];
        this.selectedRow = null;
        this.onPacketSelect = null;
    }

    setColumns(columns) {
        this.columns = columns;
        this.header.innerHTML = '';
        columns.forEach(col => {
            const th = document.createElement('th');
            th.textContent = col;
            this.header.appendChild(th);
        });
    }

    addPackets(frames) {
        frames.forEach(frame => {
            const tr = document.createElement('tr');
            tr.dataset.frameNum = frame.num;

            frame.c.forEach(cell => {
                const td = document.createElement('td');
                td.textContent = cell;
                td.title = cell; // Tooltip for truncated content
                tr.appendChild(td);
            });

            tr.addEventListener('click', () => this.selectPacket(tr, frame.num));
            this.body.appendChild(tr);
        });
    }

    selectPacket(row, frameNum) {
        if (this.selectedRow) {
            this.selectedRow.classList.remove('selected');
        }
        row.classList.add('selected');
        this.selectedRow = row;

        if (this.onPacketSelect) {
            this.onPacketSelect(frameNum);
        }
    }

    clear() {
        this.body.innerHTML = '';
        this.selectedRow = null;
    }
}

class PacketTreeView {
    constructor(container) {
        this.container = container;
    }

    render(tree) {
        this.container.innerHTML = '';
        if (!tree || tree.length === 0) {
            this.container.textContent = 'No packet selected';
            return;
        }

        tree.forEach(node => {
            this.container.appendChild(this.createNode(node));
        });
    }

    createNode(node) {
        const div = document.createElement('div');
        div.className = 'tree-node';

        const hasChildren = node.n && node.n.length > 0;

        if (hasChildren) {
            const toggle = document.createElement('span');
            toggle.className = 'tree-node-toggle';
            toggle.textContent = '▼ ';
            toggle.addEventListener('click', () => {
                const children = div.querySelector('.tree-children');
                if (children) {
                    children.classList.toggle('collapsed');
                    toggle.textContent = children.classList.contains('collapsed') ? '▶ ' : '▼ ';
                }
            });
            div.appendChild(toggle);
        } else {
            const spacer = document.createElement('span');
            spacer.textContent = '  ';
            div.appendChild(spacer);
        }

        const content = document.createElement('span');
        content.className = 'tree-node-content';
        content.textContent = node.l || node.f || 'Unknown';
        div.appendChild(content);

        if (hasChildren) {
            const children = document.createElement('div');
            children.className = 'tree-children';
            node.n.forEach(child => {
                children.appendChild(this.createNode(child));
            });
            div.appendChild(children);
        }

        return div;
    }
}

class HexView {
    constructor(container) {
        this.container = container;
    }

    render(bytes) {
        if (!bytes) {
            this.container.textContent = 'No data';
            return;
        }

        // bytes is base64 encoded
        const decoded = atob(bytes);
        const lines = [];

        for (let i = 0; i < decoded.length; i += 16) {
            const chunk = decoded.slice(i, i + 16);
            const offset = i.toString(16).padStart(8, '0');

            let hexPart = '';
            let asciiPart = '';

            for (let j = 0; j < 16; j++) {
                if (j < chunk.length) {
                    const byte = chunk.charCodeAt(j);
                    hexPart += byte.toString(16).padStart(2, '0') + ' ';
                    asciiPart += (byte >= 32 && byte <= 126) ? chunk[j] : '.';
                } else {
                    hexPart += '   ';
                    asciiPart += ' ';
                }
                if (j === 7) hexPart += ' ';
            }

            lines.push(
                `<span class="hex-offset">${offset}</span>` +
                `<span class="hex-bytes">${hexPart}</span>` +
                `<span class="hex-ascii">${escapeHtml(asciiPart)}</span>`
            );
        }

        this.container.innerHTML = lines.join('\n');
    }
}

class StreamViewer {
    constructor(client) {
        this.client = client;
        this.modal = document.getElementById('stream-modal');
        this.content = document.getElementById('stream-content');
        this.protocolSelect = document.getElementById('stream-protocol');
        this.streamIndex = document.getElementById('stream-index');
        this.viewToggle = document.getElementById('stream-view-toggle');
        this.streamBtn = document.getElementById('stream-btn');
        this.hexMode = false;
        this.currentData = null;

        this.setupEventListeners();
    }

    setupEventListeners() {
        // Open modal
        this.streamBtn.addEventListener('click', () => this.show());

        // Close modal
        document.getElementById('stream-modal-close').addEventListener('click', () => this.hide());

        // Close on backdrop click
        this.modal.addEventListener('click', (e) => {
            if (e.target === this.modal) {
                this.hide();
            }
        });

        // Fetch stream
        document.getElementById('stream-fetch-btn').addEventListener('click', () => this.fetchStream());

        // Toggle view mode
        this.viewToggle.addEventListener('click', () => this.toggleView());
    }

    show() {
        this.modal.classList.remove('hidden');
    }

    hide() {
        this.modal.classList.add('hidden');
    }

    async fetchStream() {
        const protocol = this.protocolSelect.value;
        const index = parseInt(this.streamIndex.value) || 0;

        this.content.textContent = 'Loading...';

        try {
            const result = await this.client.followStream(protocol, index);
            if (result && result.payloads && result.payloads.length > 0) {
                // Decode and concatenate payloads
                let data = '';
                for (const payload of result.payloads) {
                    if (payload.d) {
                        data += atob(payload.d);
                    }
                }
                this.currentData = data;
                this.renderData();
            } else {
                this.content.textContent = 'No stream data found';
                this.currentData = null;
            }
        } catch (error) {
            this.content.textContent = 'Error: ' + error.message;
            this.currentData = null;
        }
    }

    toggleView() {
        this.hexMode = !this.hexMode;
        this.viewToggle.textContent = this.hexMode ? 'ASCII View' : 'Hex View';
        this.renderData();
    }

    renderData() {
        if (!this.currentData) {
            return;
        }

        if (this.hexMode) {
            this.renderHex(this.currentData);
        } else {
            this.renderAscii(this.currentData);
        }
    }

    renderAscii(data) {
        // Replace non-printable characters with dots
        let text = '';
        for (let i = 0; i < data.length; i++) {
            const code = data.charCodeAt(i);
            if (code >= 32 && code <= 126) {
                text += data[i];
            } else if (code === 10 || code === 13 || code === 9) {
                text += data[i];
            } else {
                text += '.';
            }
        }
        this.content.textContent = text;
    }

    renderHex(data) {
        const lines = [];
        for (let i = 0; i < data.length; i += 16) {
            const offset = i.toString(16).padStart(8, '0');
            let hexPart = '';
            let asciiPart = '';

            for (let j = 0; j < 16; j++) {
                if (i + j < data.length) {
                    const byte = data.charCodeAt(i + j);
                    hexPart += byte.toString(16).padStart(2, '0') + ' ';
                    asciiPart += (byte >= 32 && byte <= 126) ? data[i + j] : '.';
                } else {
                    hexPart += '   ';
                    asciiPart += ' ';
                }
                if (j === 7) hexPart += ' ';
            }

            lines.push(
                `<span class="stream-hex-offset">${offset}</span>` +
                `<span class="stream-hex-bytes">${hexPart}</span>` +
                `<span class="stream-hex-ascii">${escapeHtml(asciiPart)}</span>`
            );
        }
        this.content.innerHTML = lines.join('\n');
    }

    setVisible(visible) {
        if (visible) {
            this.streamBtn.classList.remove('hidden');
        } else {
            this.streamBtn.classList.add('hidden');
        }
    }
}

// Main application
class App {
    constructor() {
        this.client = new SharkdClient();
        this.sessionPicker = null;
        this.captureControls = null;
        this.streamViewer = new StreamViewer(this.client);
        this.packetList = new PacketListView(
            document.getElementById('packets'),
            this.client
        );
        this.packetTree = new PacketTreeView(document.getElementById('packet-tree'));
        this.hexView = new HexView(document.getElementById('packet-hex'));
        this.refreshInterval = null;

        this.setupEventListeners();
    }

    setupEventListeners() {
        // Status updates
        this.client.onStatusChange = (status, message) => {
            const statusEl = document.getElementById('status');
            statusEl.textContent = message;
            statusEl.className = status;
        };

        // Packet selection
        this.packetList.onPacketSelect = async (frameNum) => {
            try {
                const frame = await this.client.getFrame(frameNum);
                this.packetTree.render(frame.tree);
                if (frame.bytes) {
                    this.hexView.render(frame.bytes);
                }
            } catch (error) {
                console.error('Failed to load frame:', error);
            }
        };

        // Filter input
        const filterInput = document.getElementById('filter');
        const applyButton = document.getElementById('apply-filter');

        applyButton.addEventListener('click', () => {
            this.applyFilter(filterInput.value);
        });

        filterInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.applyFilter(filterInput.value);
            }
        });

        // File upload
        const fileInput = document.getElementById('pcap-file');
        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                this.loadLocalFile(e.target.files[0]);
            }
        });

        // Download button
        document.getElementById('download-btn').addEventListener('click', () => {
            this.downloadPcap();
        });

        // Keyboard navigation
        document.addEventListener('keydown', (e) => {
            // Ignore if typing in an input field (for j/k/slash keys)
            const isInputFocused = document.activeElement &&
                (document.activeElement.tagName === 'INPUT' ||
                 document.activeElement.tagName === 'TEXTAREA' ||
                 document.activeElement.tagName === 'SELECT');

            // Ignore if session modal is open
            if (!document.getElementById('session-modal').classList.contains('hidden')) {
                if (e.key === 'Escape') {
                    this.sessionPicker?.hide();
                }
                return;
            }

            // Ignore if stream modal is open
            if (!document.getElementById('stream-modal').classList.contains('hidden')) {
                if (e.key === 'Escape') {
                    this.streamViewer?.hide();
                }
                return;
            }

            if (e.key === 'Escape') {
                document.getElementById('filter').blur();
                return;
            }

            // Don't intercept j/k/slash when typing in an input
            if (isInputFocused) return;

            // j/k or arrow keys for packet navigation
            if (e.key === 'j' || e.key === 'ArrowDown') {
                this.selectNextPacket();
                e.preventDefault();
            } else if (e.key === 'k' || e.key === 'ArrowUp') {
                this.selectPreviousPacket();
                e.preventDefault();
            } else if (e.key === '/' && !e.ctrlKey) {
                // Focus filter input
                document.getElementById('filter').focus();
                e.preventDefault();
            }
        });
    }

    async start() {
        debugLog('start: connecting WebSocket...');
        this.client.connect();

        // Wait for connection with timeout
        await new Promise((resolve, reject) => {
            let elapsed = 0;
            const checkConnection = setInterval(() => {
                if (this.client.ws && this.client.ws.readyState === WebSocket.OPEN) {
                    clearInterval(checkConnection);
                    resolve();
                }
                elapsed += 100;
                if (elapsed > 10000) {
                    clearInterval(checkConnection);
                    reject(new Error('WebSocket connection timeout'));
                }
            }, 100);
        });
        debugLog('start: WebSocket connected');

        // Subscribe to push notifications (non-blocking - don't let it delay startup)
        this.setupPushNotifications().then(() => {
            debugLog('push notifications set up');
        }).catch(() => {
            debugLog('push notifications not available');
        });

        // Check if server supports session registry
        const hasRegistry = await this.client.checkRegistrySupport();
        debugLog('start: hasRegistry=' + hasRegistry);

        // Initialize capture controls
        this.captureControls = new CaptureControls(this.client);
        this.captureControls.onCaptureStateChange = (capturing) => {
            this.onCaptureStateChange(capturing);
        };

        if (hasRegistry) {
            debugLog('start: showing session picker');
            // Initialize session picker
            this.sessionPicker = new SessionPicker(this.client);
            this.sessionPicker.onSessionJoined = (session) => {
                this.onSessionJoined(session);
            };

            // Show session picker modal
            this.sessionPicker.show();
        } else {
            // Hide session button if no registry support
            document.getElementById('session-btn').classList.add('hidden');

            // Initialize capture controls and get initial status
            debugLog('start: initializing capture controls...');
            await this.captureControls.init();
            debugLog('start: loading initial status...');
            await this.loadInitialStatus();
            debugLog('start: done');
        }
    }

    async onSessionJoined(session) {
        // Initialize capture controls for this session
        await this.captureControls.init();
        // Load status for the joined session
        await this.loadInitialStatus();
    }

    onCaptureStateChange(capturing) {
        if (capturing) {
            // Start auto-refresh while capturing
            this.startAutoRefresh();
        } else {
            // Stop auto-refresh and do one final refresh
            this.stopAutoRefresh();
            this.loadInitialStatus();
        }
    }

    startAutoRefresh() {
        if (this.refreshInterval) return;
        this.refreshInterval = setInterval(async () => {
            await this.loadInitialStatus();
        }, 2000);
    }

    stopAutoRefresh() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
            this.refreshInterval = null;
        }
    }

    async loadInitialStatus() {
        try {
            debugLog('loadInitialStatus: calling getStatus...');
            const status = await this.client.getStatus();
            debugLog('loadInitialStatus: status=' + JSON.stringify(status));
            if (status && status.columns) {
                this.packetList.setColumns(status.columns);
                debugLog('loadInitialStatus: set ' + status.columns.length + ' columns');
            }

            // Show download and stream buttons if there's a file loaded
            const hasFile = status && (status.filename || status.frames > 0);
            this.updateDownloadButton(hasFile);
            this.streamViewer.setVisible(hasFile);

            if (status && status.frames > 0) {
                debugLog('loadInitialStatus: loading ' + status.frames + ' frames...');
                await this.loadFrames();
                debugLog('loadInitialStatus: frames loaded');
            } else {
                debugLog('loadInitialStatus: no frames to load');
            }
        } catch (error) {
            debugLog('loadInitialStatus ERROR: ' + error.message);
            console.error('Failed to get status:', error);
        }
    }

    async setupPushNotifications() {
        try {
            // Subscribe to packet updates
            await this.client.subscribe('packets.update', (params) => {
                console.log('Packet update:', params.count);
                // Refresh frames when packet count changes
                this.loadFrames();
            });

            // Subscribe to capture state changes
            await this.client.subscribe('capture.state', (params) => {
                console.log('Capture state:', params);
                if (this.captureControls) {
                    this.captureControls.setCapturingState(params.capturing);
                }
            });
        } catch (error) {
            // Push notifications not supported, fall back to polling
            console.log('Push notifications not available:', error.message);
        }
    }

    async loadFrames(filter = '') {
        try {
            debugLog('loadFrames: filter="' + filter + '"');
            const frames = await this.client.getFrames(filter);
            debugLog('loadFrames: got ' + (frames ? frames.length : 0) + ' frames');
            // Preserve selected packet across refresh
            const selectedRow = this.packetList.selectedRow;
            const selectedFrameNum = selectedRow ? selectedRow.dataset.frameNum : null;
            this.packetList.clear();
            if (frames && frames.length > 0) {
                this.packetList.addPackets(frames);
                debugLog('loadFrames: rendered ' + frames.length + ' rows');
                // Restore selection
                if (selectedFrameNum) {
                    const row = this.packetList.body.querySelector(`tr[data-frame-num="${selectedFrameNum}"]`);
                    if (row) {
                        row.classList.add('selected');
                        this.packetList.selectedRow = row;
                    }
                }
            }
        } catch (error) {
            debugLog('loadFrames ERROR: ' + error.message);
            console.error('Failed to load frames:', error);
        }
    }

    async applyFilter(filter) {
        // Validate filter first
        if (filter) {
            try {
                await this.client.checkFilter(filter);
            } catch (error) {
                alert('Invalid filter: ' + error.message);
                return;
            }
        }
        await this.loadFrames(filter);
    }

    loadLocalFile(file) {
        // Note: This requires server-side support to handle file uploads
        // For now, show a message
        alert('File upload requires server-side file handling.\n\nTo analyze a file, start termshark with:\n  termshark --web -r ' + file.name);
    }

    downloadPcap() {
        // Trigger download via the API endpoint
        const link = document.createElement('a');
        let url = '/api/download';
        // Include session ID if we have one
        if (this.sessionPicker && this.sessionPicker.currentSessionId) {
            url += '?session=' + encodeURIComponent(this.sessionPicker.currentSessionId);
        }
        link.href = url;
        link.download = '';  // Let server set filename
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }

    updateDownloadButton(hasFile) {
        const downloadBtn = document.getElementById('download-btn');
        if (hasFile) {
            downloadBtn.classList.remove('hidden');
        } else {
            downloadBtn.classList.add('hidden');
        }
    }

    selectNextPacket() {
        const rows = document.querySelectorAll('#packet-body tr');
        if (rows.length === 0) return;

        let currentIndex = -1;
        rows.forEach((row, index) => {
            if (row.classList.contains('selected')) {
                currentIndex = index;
            }
        });

        const nextIndex = Math.min(currentIndex + 1, rows.length - 1);
        if (nextIndex >= 0) {
            const frameNum = parseInt(rows[nextIndex].dataset.frameNum);
            this.packetList.selectPacket(rows[nextIndex], frameNum);
            rows[nextIndex].scrollIntoView({ block: 'nearest' });
        }
    }

    selectPreviousPacket() {
        const rows = document.querySelectorAll('#packet-body tr');
        if (rows.length === 0) return;

        let currentIndex = -1;
        rows.forEach((row, index) => {
            if (row.classList.contains('selected')) {
                currentIndex = index;
            }
        });

        // If nothing selected, select first row; otherwise go to previous
        const prevIndex = currentIndex <= 0 ? 0 : currentIndex - 1;
        if (prevIndex < rows.length) {
            const frameNum = parseInt(rows[prevIndex].dataset.frameNum);
            this.packetList.selectPacket(rows[prevIndex], frameNum);
            rows[prevIndex].scrollIntoView({ block: 'nearest' });
        }
    }
}

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    debugLog('DOMContentLoaded fired, creating App...');
    const app = new App();
    debugLog('App created, calling start()...');
    app.start().catch(error => {
        debugLog('App.start() FAILED: ' + error.message);
        console.error('App failed to start:', error);
        const statusEl = document.getElementById('status');
        if (statusEl) {
            statusEl.textContent = 'Error: ' + error.message;
            statusEl.className = 'error';
        }
    });
});
