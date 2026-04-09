from pathlib import Path

path = Path(r"C:\Users\AEJSC\Downloads\ProjetoAgroKa-main\ProjetoAgroKa-main\templates\base.html")
text = path.read_text(encoding='utf-8')
old = '''                            <li><a class="dropdown-item" href="{{ url_for('my_feedback') }}"><i class="fas fa-share me-2"></i>Meus Feedbacks</a></li>
                            <li><a class="dropdown-item" href="{{ url_for('stock_correction') }}"><i class="fas fa-warning me-2"></i>Apontar Erro de Estoque</a></li>
                            <li><a class="dropdown-item" href="{{ url_for('report_issue') }}">Reportar Problema</a></li>
                            <li><a class="dropdown-item" href="{{ url_for('test_camera') }}">Testar Câmera</a></li>
                            <li><hr class="dropdown-divider"></li>
                            {% if not force_dark_theme %}
                            <li>
                                <a class="dropdown-item d-flex align-items-center" href="#" id="theme-switcher">
                                    <i class="fas fa-sun me-2"></i><span>Alternar Tema</span>
                                </a>
                            </li>
                            <li><hr class="dropdown-divider"></li>
                            {% endif %}
                            <li><a class="dropdown-item text-danger" href="{{ url_for('logout') }}"><i class="fas fa-sign-out-alt me-2"></i>Sair</a></li>
'''
new = '''                            <li><a class="dropdown-item" href="{{ url_for('my_feedback') }}"><i class="fas fa-share me-2"></i>Meus Feedbacks</a></li>
                            <li><a class="dropdown-item" href="{{ url_for('stock_correction') }}"><i class="fas fa-warning me-2"></i>Apontar Erro de Estoque</a></li>
                            <li><a class="dropdown-item" href="{{ url_for('report_issue') }}">Reportar Problema</a></li>
                            <li><a class="dropdown-item" href="{{ url_for('test_camera') }}">Testar Câmera</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li>
                                <h6 class="dropdown-header">{{ translate('language_selector_label') }}</h6>
                            </li>
                            <li>
                                <a class="dropdown-item d-flex align-items-center" href="{{ url_for('set_language', language_code='pt') }}">
                                    <span class="badge bg-secondary text-white me-2">PT</span>Português
                                </a>
                            </li>
                            <li>
                                <a class="dropdown-item d-flex align-items-center" href="{{ url_for('set_language', language_code='en') }}">
                                    <span class="badge bg-secondary text-white me-2">EN</span>English
                                </a>
                            </li>
                            <li><hr class="dropdown-divider"></li>
                            {% if not force_dark_theme %}
                            <li>
                                <a class="dropdown-item d-flex align-items-center" href="#" id="theme-switcher">
                                    <i class="fas fa-sun me-2"></i><span>Alternar Tema</span>
                                </a>
                            </li>
                            <li><hr class="dropdown-divider"></li>
                            {% endif %}
                            <li><a class="dropdown-item text-danger" href="{{ url_for('logout') }}"><i class="fas fa-sign-out-alt me-2"></i>Sair</a></li>
'''
count = text.count(old)
print('count', count)
if count == 0:
    raise SystemExit('old block not found')
text = text.replace(old, new)
path.write_text(text, encoding='utf-8')
print('replaced', count)
