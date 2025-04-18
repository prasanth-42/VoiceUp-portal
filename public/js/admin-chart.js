// Function to create the complaints chart
function createComplaintsChart(pending, processing, resolved, rejected) {
    const canvas = document.getElementById('complaintsChart');
    if (!canvas) {
        console.error('Canvas element not found');
        return;
    }
    
    const ctx = canvas.getContext('2d');
    
    // Create the chart
    new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['Pending', 'Processing', 'Resolved', 'Rejected'],
            datasets: [{
                data: [pending, processing, resolved, rejected],
                backgroundColor: [
                    '#ffeeba',
                    '#cce5ff',
                    '#d4edda',
                    '#f8d7da'
                ],
                borderColor: [
                    '#856404',
                    '#004085',
                    '#155724',
                    '#721c24'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });
}

// Initialize when the DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Get data from the data attributes on the container
    const container = document.querySelector('.chart-container');
    if (container) {
        const pending = parseInt(container.dataset.pending) || 0;
        const processing = parseInt(container.dataset.processing) || 0;
        const resolved = parseInt(container.dataset.resolved) || 0;
        const rejected = parseInt(container.dataset.rejected) || 0;
        
        createComplaintsChart(pending, processing, resolved, rejected);
    }
}); 