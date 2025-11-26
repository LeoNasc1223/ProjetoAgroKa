document.addEventListener('DOMContentLoaded', function() {
    const notificationBadge = document.getElementById('notification-badge');
    const notificationList = document.getElementById('notification-list');
    const noNotificationsItem = document.getElementById('no-notifications-item');
    const markAllReadLink = document.getElementById('mark-all-read-link');
    const divider = notificationList.querySelector('.divider-before-footer');

    // As URLs são passadas como atributos data-* no elemento da lista para desacoplar o JS do Jinja2
    const fetchUrl = notificationList.dataset.fetchUrl;
    const markAllReadUrl = markAllReadLink.dataset.markAllUrl;
    const markReadUrlBase = notificationList.dataset.markReadUrlBase;

    function fetchNotifications() {
        fetch(fetchUrl)
            .then(response => response.json())
            .then(data => {
                // Update badge
                if (data.unread_count > 0) {
                    notificationBadge.textContent = data.unread_count;
                    notificationBadge.style.display = 'inline-block';
                } else {
                    notificationBadge.style.display = 'none';
                }

                // Clear existing notifications
                const items = notificationList.querySelectorAll('.notification-item');
                items.forEach(item => item.remove());

                // Populate list
                if (data.notifications && data.notifications.length > 0) {
                    noNotificationsItem.style.display = 'none';
                    divider.style.display = 'block';
                    data.notifications.forEach(notif => {
                        const li = document.createElement('li');
                        li.className = 'notification-item';
                        li.innerHTML = `
                            <a class="dropdown-item" href="${notif.link || '#'}" data-id="${notif.id}">
                                <div class="d-flex w-100 justify-content-between">
                                    <small class="text-muted">${new Date(notif.timestamp).toLocaleDateString()}</small>
                                    <small class="text-muted">${new Date(notif.timestamp).toLocaleTimeString()}</small>
                                </div>
                                <p class="mb-0 text-wrap">${notif.message}</p>
                            </a>
                        `;
                        notificationList.insertBefore(li, divider);

                        li.querySelector('a').addEventListener('click', function(e) {
                            markAsRead(notif.id);
                        });
                    });
                } else {
                    noNotificationsItem.style.display = 'block';
                    divider.style.display = 'none';
                }
            })
            .catch(error => console.error('Erro ao buscar notificações:', error));
    }

    function markAsRead(notificationId) {
        fetch(`${markReadUrlBase}/${notificationId}`, { method: 'POST' });
    }

    markAllReadLink.addEventListener('click', function(e) {
        e.preventDefault();
        fetch(markAllReadUrl, { method: 'POST' }).then(fetchNotifications);
    });

    fetchNotifications();
    setInterval(fetchNotifications, 60000); // Check for new notifications every minute
});