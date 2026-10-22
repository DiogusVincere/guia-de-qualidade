/* Interface local do scanner. Vanilla JS, sem build. Fala só com o processo local (127.0.0.1). */
(function () {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const TOKEN = window.TOKEN;

  function toast(t, tipo) {
    const el = $('toast'); el.textContent = t; el.className = 'toast' + (tipo ? ' toast--' + tipo : ''); el.hidden = false;
    clearTimeout(toast._t); toast._t = setTimeout(() => { el.hidden = true; }, 5000);
  }
  async function api(caminho, opcoes) {
    const o = Object.assign({ method: 'GET' }, opcoes || {});
    o.headers = Object.assign({ 'X-Token': TOKEN }, o.headers || {});
    if (o.json !== undefined) { o.body = JSON.stringify(o.json); o.headers['Content-Type'] = 'application/json'; delete o.json; }
    const r = await fetch(caminho, o);
    if (o.bruto) return r;
    let d = null; try { d = await r.json(); } catch (e) { d = null; }
    if (!r.ok) { const e = new Error((d && d.erro) || ('erro ' + r.status)); e.status = r.status; throw e; }
    return d;
  }
  const escapar = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  $('intensidade').addEventListener('input', () => { $('nivel-num').textContent = $('intensidade').value; });

  let ocupado = false, totalMsg = 0, tmr = null, filtro = 'todos', dados = null;

  function ambiente() { return document.querySelector('input[name=ambiente]:checked').value; }

  $('form').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (ocupado) return;
    if (!$('alvo').value) { toast('Informe a URL do site.', 'erro'); return; }
    if (!$('autorizo').value.trim()) { toast('Declare a autorização.', 'erro'); return; }
    const corpo = {
      alvo: $('alvo').value.trim(), autorizo: $('autorizo').value.trim(), ambiente: ambiente(),
      intensidade: Number($('intensidade').value), escrever: $('escrever').checked,
      usuario: $('usuario').value || '', senha: $('senha').value || '', config: $('config').value.trim() || ''
    };
    try { await api('/api/testar', { method: 'POST', json: corpo }); acompanhar(); }
    catch (err) { toast(err.message, 'erro'); }
  });

  function acompanhar() {
    $('vazio').hidden = true; $('resultado').hidden = true; $('andamento').hidden = false;
    $('log').textContent = ''; $('erro').hidden = true; $('barra').style.width = '0%';
    totalMsg = 0; ocupado = true; $('btn-testar').disabled = true;
    consultar(); tmr = setInterval(consultar, 1000);
  }
  const FASES = { preparando: 'preparando', testando: 'testando', montando: 'montando o relatório', concluido: 'concluído', erro: 'falhou' };

  async function consultar() {
    try {
      const est = await api('/api/estado?desde=' + totalMsg);
      const t = est.trabalho; if (!t) return;
      for (const m of t.mensagens) {
        const l = document.createElement('div'); l.className = 'log__linha log__linha--' + m.nivel;
        l.textContent = m.hora + '  ' + m.texto; $('log').appendChild(l);
      }
      $('log').scrollTop = $('log').scrollHeight; totalMsg = t.total_mensagens;
      $('fase').textContent = FASES[t.fase] || t.fase;
      $('fase').className = 'selo ' + (t.fase === 'erro' ? 'selo--vermelho' : t.fase === 'concluido' ? 'selo--verde' : 'selo--azul');
      $('cron').textContent = t.segundos + ' s';
      const m = (t.mensagens.length ? t.mensagens : []).map((x) => x.texto).reverse().find((x) => /\[(\d+)\/(\d+)\]/.test(x));
      if (m) { const g = m.match(/\[(\d+)\/(\d+)\]/); $('barra').style.width = Math.round(100 * g[1] / g[2]) + '%'; }
      if (t.concluido) {
        clearInterval(tmr); tmr = null; ocupado = false; $('btn-testar').disabled = false;
        if (t.erro) { $('erro').textContent = 'Não terminou: ' + t.erro; $('erro').hidden = false; }
        else { $('barra').style.width = '100%'; mostrar(t.resultado); }
      }
    } catch (e) {
      const l = document.createElement('div'); l.className = 'log__linha log__linha--erro';
      l.textContent = 'sem resposta do processo local: ' + e.message; $('log').appendChild(l);
    }
  }

  const COR = { critico: 'vermelho', alto: 'ambar', medio: 'azul', baixo: 'cinza', info: 'cinza' };
  const ROTULO = { critico: 'Crítico', alto: 'Alto', medio: 'Médio', baixo: 'Baixo', info: 'Info' };

  function mostrar(res) {
    dados = res;
    $('res-host').textContent = res.host + ' · ' + res.ambiente;
    $('totais').innerHTML = res.ordem.map((g) =>
      '<div class="total total--' + COR[g] + '"><strong>' + res.contagem[g] + '</strong><span>' + ROTULO[g] + '</span></div>').join('');
    // cenários
    if (res.cenarios.length) {
      $('cenarios').innerHTML = '<h3>Como um atacante usaria isto</h3>' + res.cenarios.map((c) =>
        '<div class="cenario cenario--' + COR[c.gravidade] + '"><strong>' + escapar(c.titulo) + '</strong>' +
        ' <small>' + c.gravidade + ' · CVSS ~' + escapar(c.cvss) + '</small>' +
        '<p>' + escapar(c.o_que_entrega) + '</p><ol>' + c.passos.map((p) => '<li>' + escapar(p) + '</li>').join('') + '</ol></div>').join('');
    } else { $('cenarios').innerHTML = ''; }
    // chips por gravidade
    filtro = 'todos';
    $('chips').innerHTML = ['todos'].concat(res.ordem).map((g) => {
      const n = g === 'todos' ? res.achados.length : res.contagem[g];
      return '<button type="button" class="chip' + (g === 'todos' ? ' chip--ativo' : '') + '" data-g="' + g + '">' +
        (g === 'todos' ? 'Todos' : ROTULO[g]) + ' <small>' + n + '</small></button>';
    }).join('');
    renderAchados();
    $('andamento').hidden = false; $('resultado').hidden = false;
    $('resultado').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function renderAchados() {
    const vis = dados.achados.filter((a) => filtro === 'todos' || a.gravidade === filtro);
    $('achados').innerHTML = vis.length ? vis.map((a) =>
      '<div class="achado achado--' + COR[a.gravidade] + '">' +
      '<div class="achado__topo"><span class="selo selo--' + COR[a.gravidade] + '">' + a.gravidade + '</span>' +
      '<strong>[' + escapar(a.item) + '] ' + escapar(a.titulo) + '</strong></div>' +
      '<div class="achado__url">' + escapar(a.url) + '</div>' +
      '<p><b>Evidência:</b> ' + escapar(a.evidencia) + '</p>' +
      '<p><b>Por quê:</b> ' + escapar(a.explicacao) + '</p>' +
      '<p><b>Corrigir:</b> ' + escapar(a.correcao) + '</p>' +
      (a.reproduzir ? '<pre class="repro">' + escapar(a.reproduzir) + '</pre>' : '') + '</div>').join('')
      : '<p class="texto-suave">Nenhum achado nessa gravidade.</p>';
  }
  $('chips').addEventListener('click', (e) => {
    const b = e.target.closest('button'); if (!b) return;
    filtro = b.dataset.g; document.querySelectorAll('.chip').forEach((c) => c.classList.toggle('chip--ativo', c === b));
    renderAchados();
  });

  $('btn-baixar').addEventListener('click', async () => {
    try {
      const r = await api('/api/baixar', { bruto: true });
      const blob = await r.blob(); const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = 'relatorio-seguranca.md';
      document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 8000);
    } catch (e) { toast(e.message, 'erro'); }
  });
  $('btn-novo').addEventListener('click', () => { $('resultado').hidden = true; $('andamento').hidden = true; $('vazio').hidden = false; window.scrollTo({ top: 0, behavior: 'smooth' }); });
  $('btn-encerrar').addEventListener('click', async () => {
    if (!confirm('Encerrar o processo local?')) return;
    try { await api('/api/encerrar', { method: 'POST', json: {} }); } catch (e) { /* já caiu */ }
    document.body.innerHTML = '<div class="encerrado"><h1>Encerrado</h1><p>Pode fechar esta aba.</p></div>';
  });
  window.addEventListener('beforeunload', (e) => { if (ocupado) { e.preventDefault(); e.returnValue = ''; } });

  api('/api/estado').then((est) => {
    if (est.trabalho && est.trabalho.concluido && est.trabalho.resultado) { $('vazio').hidden = true; mostrar(est.trabalho.resultado); }
    else if (est.trabalho) acompanhar();
  }).catch(() => {});
})();
