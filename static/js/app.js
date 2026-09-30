// SecureChain Frontend Application Logic

document.addEventListener('DOMContentLoaded', () => {
    // 1. Modal Dialog Logic
    window.openModal = function(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.add('show');
        }
    };

    window.closeModal = function(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.remove('show');
        }
    };

    // Close modal on backdrop click
    document.querySelectorAll('.modal-backdrop').forEach(backdrop => {
        backdrop.addEventListener('click', (e) => {
            if (e.target === backdrop) {
                backdrop.classList.remove('show');
            }
        });
    });

    // 2. Pre-fill Login Credentials
    window.fillCredentials = function(username, password, role) {
        const userInput = document.getElementById('username');
        const passInput = document.getElementById('password');
        const roleSelect = document.getElementById('role');

        if (userInput) userInput.value = username;
        if (passInput) passInput.value = password;
        if (roleSelect) roleSelect.value = role;
    };

    // 3. Table Search Filter
    const searchInputs = document.querySelectorAll('[data-table-search]');
    searchInputs.forEach(input => {
        const tableId = input.getAttribute('data-table-search');
        const table = document.getElementById(tableId);
        if (table) {
            input.addEventListener('keyup', () => {
                const term = input.value.toLowerCase();
                const rows = table.querySelectorAll('tbody tr');
                rows.forEach(row => {
                    const text = row.textContent.toLowerCase();
                    row.style.display = text.includes(term) ? '' : 'none';
                });
            });
        }
    });

    // 4. Audit Chain Verification Handler (AJAX)
    const verifyBtn = document.getElementById('verify-audit-btn');
    if (verifyBtn) {
        verifyBtn.addEventListener('click', async (e) => {
            e.preventDefault();
            const statusBox = document.getElementById('audit-verification-result');
            if (statusBox) {
                statusBox.innerHTML = '<span class="badge badge-warning"><i class="fas fa-spinner fa-spin"></i> Calculating SHA-256 Hashes...</span>';
            }

            try {
                const response = await fetch('/audit/verify', {
                    headers: { 'X-Requested-With': 'XMLHttpRequest' }
                });
                const data = await response.json();

                if (statusBox) {
                    if (data.valid) {
                        statusBox.innerHTML = `
                            <div class="alert alert-success" style="margin-top: 1rem;">
                                <i class="fas fa-check-circle" style="font-size: 1.2rem;"></i>
                                <div>
                                    <strong>✓ Audit Trail Integrity Verified</strong><br>
                                    <small>${data.message}</small>
                                </div>
                            </div>
                        `;
                    } else {
                        statusBox.innerHTML = `
                            <div class="alert alert-danger" style="margin-top: 1rem;">
                                <i class="fas fa-exclamation-triangle" style="font-size: 1.2rem;"></i>
                                <div>
                                    <strong>✗ Audit Chain Compromised!</strong><br>
                                    <small>${data.message}</small>
                                </div>
                            </div>
                        `;
                    }
                }
            } catch (err) {
                console.error('Audit verification error:', err);
            }
        });
    }
});
