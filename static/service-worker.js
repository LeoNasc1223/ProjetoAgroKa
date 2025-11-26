const CACHE_NAME = 'agroka-cache-v1';
const urlsToCache = [
  '/', // A rota principal da sua aplicação
  // Adicione aqui caminhos para seus arquivos CSS e JS estáticos principais
  // Exemplo: '/static/css/style.css', '/static/js/main.js'
  '/static/images/icon-192x192.png',
  '/static/images/icon-512x512.png',
  '/static/manifest.json'
  // Não adicione rotas de API como '/get_product_name' aqui para caching simples,
  // pois o conteúdo delas é dinâmico.
];

// Evento de instalação: abre o cache e adiciona os arquivos principais
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('ServiceWorker: Cache aberto');
        return cache.addAll(urlsToCache);
      })
      .catch(err => {
        console.error('ServiceWorker: Falha ao cachear arquivos durante a instalação', err);
      })
  );
});

// Evento de ativação: limpa caches antigos se o nome do cache mudar
self.addEventListener('activate', event => {
  const cacheWhitelist = [CACHE_NAME];
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheWhitelist.indexOf(cacheName) === -1) {
            console.log('ServiceWorker: Removendo cache antigo', cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
});

// Evento fetch: intercepta requisições e serve do cache se disponível
self.addEventListener('fetch', event => {
  // Apenas para requisições GET
  if (event.request.method !== 'GET') {
    return;
  }

  event.respondWith(
    caches.match(event.request)
      .then(response => {
        // Cache hit - retorna a resposta do cache
        if (response) {
          return response;
        }
        // Não está no cache, busca na rede (e opcionalmente adiciona ao cache)
        return fetch(event.request); // Para uma estratégia simples de "network falling back to cache" ou "cache falling back to network"
      })
  );
});