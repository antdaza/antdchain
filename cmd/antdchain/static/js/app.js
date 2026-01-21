class ANTDChainWeb {
    constructor() {
        this.baseURL = window.location.origin;
        this.init();
    }
    
    init() {
        this.updateStats();
        setInterval(() => this.updateStats(), 5000);
        
        // Update page-specific content
        if (window.location.pathname === '/') {
            this.loadLatestBlocks();
            this.loadLatestTransactions();
        }
    }
    
    async fetchAPI(endpoint) {
        try {
            const response = await fetch(`${this.baseURL}/api${endpoint}`);
            return await response.json();
        } catch (error) {
            console.error('API Error:', error);
            return null;
        }
    }
    
    async updateStats() {
        const status = await this.fetchAPI('/chain/status');
        if (status) {
            // Update navbar
            document.getElementById('block-height')?.textContent = `Height: ${status.height}`;
            document.getElementById('peer-count')?.textContent = `${status.peers || 0} peers`;
            
            // Update dashboard stats
            document.getElementById('stat-height')?.textContent = status.height;
            document.getElementById('stat-mempool')?.textContent = `${status.mempool_size || 0} txs`;
            document.getElementById('stat-peers')?.textContent = status.peers || 0;
        }
    }
    
    async loadLatestBlocks() {
        const data = await this.fetchAPI('/chain/blocks?limit=10');
        if (data && data.blocks) {
            const container = document.getElementById('latest-blocks');
            if (container) {
                container.innerHTML = this.renderBlocksTable(data.blocks);
            }
        }
    }
    
    async loadLatestTransactions() {
        const data = await this.fetchAPI('/chain/transactions?limit=10');
        if (data && data.transactions) {
            const container = document.getElementById('latest-transactions');
            if (container) {
                container.innerHTML = this.renderTransactionsTable(data.transactions);
            }
        }
    }
    
    renderBlocksTable(blocks) {
        return `
            <table>
                <thead>
                    <tr>
                        <th>Height</th>
                        <th>Hash</th>
                        <th>Miner</th>
                        <th>TXs</th>
                        <th>Time</th>
                    </tr>
                </thead>
                <tbody>
                    ${blocks.map(block => `
                        <tr>
                            <td><a href="/blocks/${block.height}">${block.height}</a></td>
                            <td><small>${block.hash.substring(0, 16)}...</small></td>
                            <td><small>${block.miner.substring(0, 16)}...</small></td>
                            <td>${block.tx_count}</td>
                            <td>${this.formatTime(block.timestamp)}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    }
    
    renderTransactionsTable(transactions) {
        return `
            <table>
                <thead>
                    <tr>
                        <th>Hash</th>
                        <th>From</th>
                        <th>To</th>
                        <th>Value</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    ${transactions.map(tx => `
                        <tr>
                            <td><small><a href="/transactions/${tx.hash}">${tx.hash.substring(0, 16)}...</a></small></td>
                            <td><small>${tx.from.substring(0, 16)}...</small></td>
                            <td><small>${tx.to ? tx.to.substring(0, 16) + '...' : 'Contract'}</small></td>
                            <td>${this.formatValue(tx.value)} ANTD</td>
                            <td><span class="status ${tx.status}">${tx.status}</span></td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    }
    
    formatTime(timestamp) {
        const date = new Date(timestamp * 1000);
        return date.toLocaleTimeString();
    }
    
    formatValue(value) {
        const num = BigInt(value);
        if (num < 1000000000000000000n) {
            return (Number(num) / 1e18).toFixed(4);
        }
        return (Number(num) / 1e18).toFixed(2);
    }
}

// Initialize when page loads
document.addEventListener('DOMContentLoaded', () => {
    window.antdchain = new ANTDChainWeb();
});
