document.addEventListener('DOMContentLoaded', function () {
    // Garante que a variável salesChartData exista
    if (typeof salesChartData !== 'undefined' && salesChartData.length > 0) {
        
        const salesCtx = document.getElementById('salesHistoryChart');
        if (salesCtx) {
            // Ordena os dados por data para garantir que o gráfico seja exibido corretamente
            salesChartData.sort((a, b) => new Date(a.data_verificacao) - new Date(b.data_verificacao));

            const labels = salesChartData.map(item => {
                const date = new Date(item.data_verificacao);
                return date.toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit' });
            });
            const data = salesChartData.map(item => item.quantidade_vendida);

            new Chart(salesCtx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'Quantidade Vendida',
                        data: data,
                        fill: true,
                        backgroundColor: 'rgba(255, 193, 7, 0.1)',
                        borderColor: 'rgba(255, 193, 7, 1)',
                        pointBackgroundColor: 'rgba(255, 193, 7, 1)',
                        pointBorderColor: '#fff',
                        pointHoverRadius: 5,
                        tension: 0.3
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: { beginAtZero: true }
                    }
                }
            });
        }
    }
});