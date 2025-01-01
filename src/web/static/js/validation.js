document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('url-form');
    const urlInput = document.getElementById('url');

    if (form) {
        form.addEventListener('submit', function(e) {
            if (!urlInput.value.match(/^https?:\/\/.+/i)) {
                e.preventDefault();
                alert('Please enter a valid URL starting with http:// or https://');
            }
        });
    }
});