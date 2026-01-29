// Termshark Web UI - Main JavaScript

class SharkdClient {
    constructor() {
        this.ws = null;
        this.requestId = 0;
        this.pendingRequests = new Map();
        this.onStatusChange = null;
    }

    connect() {
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
            if (this.onStatusChange) {
                this.onStatusChange('error', 'Disconnected');
            }
            // Attempt reconnect after 3 seconds
            setTimeout(() => this.connect(), 3000);
        };

        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            if (this.onStatusChange) {
                this.onStatusChange('error', 'Connection error');
            }
        };

        this.ws.onmessage = (event) => {
            const response = JSON.parse(event.data);
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
        // protocol: 'tcp', 'udp', 'http', etc.
        // streamIndex: the stream number to follow
        return this.call('follow', {
            follow: protocol,
            filter: `${protocol}.stream eq ${streamIndex}`
        });
    }

    async getTaps(taps) {
        // taps is an array like ['expert', 'conv:eth', 'endpt:ip']
        return this.call('tap', { tap0: taps[0] });
    }

    async getIntervals(interval = 1000) {
        // interval in milliseconds
        return this.call('intervals', { interval: interval });
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
                `<span class="hex-ascii">${asciiPart}</span>`
            );
        }

        this.container.innerHTML = lines.join('\n');
    }
}

// Main application
class App {
    constructor() {
        this.client = new SharkdClient();
        this.packetList = new PacketListView(
            document.getElementById('packets'),
            this.client
        );
        this.packetTree = new PacketTreeView(document.getElementById('packet-tree'));
        this.hexView = new HexView(document.getElementById('packet-hex'));

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

        // Keyboard navigation
        document.addEventListener('keydown', (e) => {
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
            } else if (e.key === 'Escape') {
                document.getElementById('filter').blur();
            }
        });
    }

    async start() {
        this.client.connect();

        // Wait for connection
        await new Promise(resolve => {
            const checkConnection = setInterval(() => {
                if (this.client.ws && this.client.ws.readyState === WebSocket.OPEN) {
                    clearInterval(checkConnection);
                    resolve();
                }
            }, 100);
        });

        // Get initial status
        try {
            const status = await this.client.getStatus();
            this.packetList.setColumns(status.columns);

            if (status.frames > 0) {
                await this.loadFrames();
            }
        } catch (error) {
            console.error('Failed to get status:', error);
        }
    }

    async loadFrames(filter = '') {
        try {
            const frames = await this.client.getFrames(filter);
            this.packetList.clear();
            if (frames && frames.length > 0) {
                this.packetList.addPackets(frames);
            }
        } catch (error) {
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

        let currentIndex = rows.length;
        rows.forEach((row, index) => {
            if (row.classList.contains('selected')) {
                currentIndex = index;
            }
        });

        const prevIndex = Math.max(currentIndex - 1, 0);
        if (prevIndex < rows.length) {
            const frameNum = parseInt(rows[prevIndex].dataset.frameNum);
            this.packetList.selectPacket(rows[prevIndex], frameNum);
            rows[prevIndex].scrollIntoView({ block: 'nearest' });
        }
    }
}

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    const app = new App();
    app.start();
});
