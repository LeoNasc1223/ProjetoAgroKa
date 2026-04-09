<<<<<<< HEAD
document.addEventListener('DOMContentLoaded', function () {
    // Garante que a variável chartData exista (foi passada pelo template)
    if (typeof chartData !== 'undefined') {
        
        // Gráfico de Entradas por Dia
        const entriesCtx = document.getElementById('entriesByDayChart');
        if (entriesCtx) {
            const labels = chartData.map(item => item.date);
            const data = chartData.map(item => item.count);

            new Chart(entriesCtx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'Entradas Registradas',
                        data: data,
                        fill: true,
                        backgroundColor: 'rgba(78, 115, 223, 0.1)',
                        borderColor: 'rgba(78, 115, 223, 1)',
                        pointBackgroundColor: 'rgba(78, 115, 223, 1)',
                        pointBorderColor: '#fff',
                        pointHoverRadius: 5,
                        tension: 0.3
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });
        }
    }
=======
document.addEventListener('DOMContentLoaded', function () {
    // Garante que a variável chartData exista (foi passada pelo template)
    if (typeof chartData !== 'undefined') {
        
        // Gráfico de Entradas por Dia
        const entriesCtx = document.getElementById('entriesByDayChart');
        if (entriesCtx) {
            const labels = chartData.map(item => item.date);
            const data = chartData.map(item => item.count);

            new Chart(entriesCtx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'Entradas Registradas',
                        data: data,
                        fill: true,
                        backgroundColor: 'rgba(78, 115, 223, 0.1)',
                        borderColor: 'rgba(78, 115, 223, 1)',
                        pointBackgroundColor: 'rgba(78, 115, 223, 1)',
                        pointBorderColor: '#fff',
                        pointHoverRadius: 5,
                        tension: 0.3
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });
        }
    }
>>>>>>> a2c8492483ee7245b6928a24900d17788b671f95
});