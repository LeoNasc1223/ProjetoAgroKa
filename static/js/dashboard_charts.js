document.addEventListener('DOMContentLoaded', function() {
    fetch('/api/dashboard_charts')
        .then(response => response.json())
        .then(data => {
            // Gráfico de Entradas por Dia
            const entradasCtx = document.getElementById('entradasPorDiaChart').getContext('2d');
            new Chart(entradasCtx, {
                type: 'bar',
                data: {
                    labels: data.entradas_por_dia.labels,
                    datasets: [{
                        label: 'Entradas',
                        data: data.entradas_por_dia.data,
                        backgroundColor: 'rgba(75, 192, 192, 0.6)',
                        borderColor: 'rgba(75, 192, 192, 1)',
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Número de Entradas'
                            }
                        },
                        x: {
                            title: {
                                display: true,
                                text: 'Data'
                            }
                        }
                    }
                }
            });

            // Gráfico de Top 5 Produtos
            const produtosCtx = document.getElementById('topProdutosChart').getContext('2d');
            new Chart(produtosCtx, {
                type: 'pie',
                data: {
                    labels: data.top_produtos.labels,
                    datasets: [{
                        label: 'Quantidade Registrada',
                        data: data.top_produtos.data,
                        backgroundColor: [
                            'rgba(255, 99, 132, 0.6)',
                            'rgba(54, 162, 235, 0.6)',
                            'rgba(255, 206, 86, 0.6)',
                            'rgba(75, 192, 192, 0.6)',
                            'rgba(153, 102, 255, 0.6)'
                        ],
                        borderColor: [
                            'rgba(255, 99, 132, 1)',
                            'rgba(54, 162, 235, 1)',
                            'rgba(255, 206, 86, 1)',
                            'rgba(75, 192, 192, 1)',
                            'rgba(153, 102, 255, 1)'
                        ],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'top',
                        },
                        title: {
                            display: true,
                            text: 'Top 5 Produtos Mais Registrados'
                        }
                    }
                }
            });
        })
        .catch(error => {
            console.error('Erro ao carregar dados para os gráficos do dashboard:', error);
            // Opcional: exibir uma mensagem de erro na interface do usuário
            const dashboardContainer = document.querySelector('.container.mt-4');
            if (dashboardContainer) {
                const errorDiv = document.createElement('div');
                errorDiv.className = 'alert alert-danger mt-4';
                errorDiv.textContent = 'Não foi possível carregar os gráficos do dashboard. Tente novamente mais tarde.';
                dashboardContainer.appendChild(errorDiv);
            }
        });
});