const eicar = [
  'X5O!P%@AP[4\\PZX54(P^)7CC)7}$',
  'EICAR-STANDARD-ANTIVIRUS-',
  'TEST-FILE!$H+H*'
].join('');

const LINK = 'https://secure.eicar.org/eicar.com.txt';
const note = document.getElementById('note');

document.getElementById('str').textContent = eicar;

async function applyEicarI18n() {
  await i18nInit();
  document.getElementById('pageTitle').textContent = t('eicar.title');
  document.getElementById('heading').textContent = t('eicar.heading');
  document.getElementById('description').textContent = t('eicar.description');
  document.getElementById('dl').textContent = t('eicar.download');
  document.getElementById('copy').textContent = t('eicar.copyLink');
}

document.getElementById('dl').addEventListener('click', () => {
  const url = URL.createObjectURL(new Blob([eicar], { type: 'application/octet-stream' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = 'eicar_test_file';
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  note.textContent = t('eicar.downloadNote');
});

document.getElementById('copy').addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(LINK);
  } catch (e) {
    const ta = document.createElement('textarea');
    ta.value = LINK;
    document.body.append(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }
  note.textContent = t('eicar.linkCopied', { link: LINK });
});

applyEicarI18n();