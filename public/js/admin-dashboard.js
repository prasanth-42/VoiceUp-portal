// Officer Details Modal
document.addEventListener('DOMContentLoaded', function() {
    const modal = document.getElementById('officerModal');
    const closeModal = document.getElementsByClassName('close-modal')[0];
    
    // Add click event to all officer cards
    const officerCards = document.querySelectorAll('.user-card[data-officer-id]');
    officerCards.forEach(card => {
        card.addEventListener('click', function(e) {
            // Prevent form submission when clicking on the card
            if (e.target.tagName !== 'BUTTON' && e.target.tagName !== 'FORM' && e.target.tagName !== 'A') {
                showOfficerDetails(this);
            }
        });
    });

    function showOfficerDetails(card) {
        const officerId = card.getAttribute('data-officer-id');
        const officerName = card.querySelector('h3').textContent.trim();
        const officerEmail = card.querySelector('p:nth-child(2)').textContent.trim().replace('📧', '').trim();
        const officerAge = card.querySelector('p:nth-child(3)').textContent.trim().replace('🎂', '').trim();
        const officerIdShort = card.querySelector('p:nth-child(4)').textContent.trim().replace('🆔', '').trim();

        const detailsHtml = `
            <div class="officer-detail-item">
                <i class="fas fa-user"></i>
                <div class="detail-content">
                    <strong>Username:</strong>
                    <span>${officerName}</span>
                </div>
            </div>
            <div class="officer-detail-item">
                <i class="fas fa-envelope"></i>
                <div class="detail-content">
                    <strong>Email:</strong>
                    <span>${officerEmail}</span>
                </div>
            </div>
            <div class="officer-detail-item">
                <i class="fas fa-birthday-cake"></i>
                <div class="detail-content">
                    <strong>Age:</strong>
                    <span>${officerAge}</span>
                </div>
            </div>
            <div class="officer-detail-item">
                <i class="fas fa-id-card"></i>
                <div class="detail-content">
                    <strong>ID:</strong>
                    <span>${officerIdShort}</span>
                </div>
            </div>
            <div class="officer-actions">
                <a href="/profile/${officerName}" class="btn btn-primary">
                    <i class="fas fa-user-circle"></i> View Profile
                </a>
                <form action="/delete-user/${officerId}" method="POST" 
                    onsubmit="return confirm('Are you sure you want to delete this officer?');">
                    <button type="submit" class="btn btn-danger">
                        <i class="fas fa-trash-alt"></i> Delete
                    </button>
                </form>
            </div>
        `;

        document.getElementById('officerDetails').innerHTML = detailsHtml;
        modal.style.display = 'block';
        
        // Add animation class
        modal.classList.add('animate__animated', 'animate__fadeIn');
    }

    closeModal.onclick = function() {
        modal.classList.remove('animate__fadeIn');
        modal.classList.add('animate__fadeOut');
        
        setTimeout(() => {
            modal.style.display = 'none';
            modal.classList.remove('animate__fadeOut');
        }, 500);
    }

    window.onclick = function(event) {
        if (event.target == modal) {
            modal.classList.remove('animate__fadeIn');
            modal.classList.add('animate__fadeOut');
            
            setTimeout(() => {
                modal.style.display = 'none';
                modal.classList.remove('animate__fadeOut');
            }, 500);
        }
    }
}); 