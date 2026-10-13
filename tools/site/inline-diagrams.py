import re
import os; S=os.path.join(os.path.dirname(os.path.abspath(__file__)),'svg')+'/'
def svg(n,minw=None):
    s=open(S+n+'.svg',encoding='utf-8').read()
    vb=re.search(r'viewBox="([^"]+)"',s).group(1).split()
    w=float(vb[2])
    s=re.sub(r'style="max-width: [0-9.]+px;" ','',s,count=1)
    s=re.sub(r' width="100%"',f' width="{w:.0f}"',s,count=1)
    if minw: s=re.sub(r'<svg ',f'<svg style="min-width:{minw}px" ',s,count=1)
    return f'<figure class="dg"><div>{s}</div></figure>'
p=os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','..','docs','index.html'); h=open(p,encoding='utf-8').read()
css='''figure.dg{margin:1.2em 0}figure.dg div{overflow-x:auto;text-align:center}figure.dg svg{display:inline-block;max-width:100%;height:auto}
html.inverted figure.dg{filter:invert(.93) hue-rotate(180deg)}
'''
h=h.replace('figure{margin:1.5em 0}\n','figure{margin:1.5em 0}\n'+css)
h=h.replace('<a href="#quickstart">Quickstart</a>','<a href="#how">How it works</a> · <a href="#quickstart">Quickstart</a>')
how=f'''
<h2 id="how">How it works</h2>
<p>The board does signalling. The phones do audio. An ordinary extension-to-extension call streams RTP straight from phone to phone, so the board never carries it. That is what lets a microcontroller run a PBX.</p>
{svg('topology')}
<p>The engine is a back-to-back call broker, not an RFC 3261 proxy: it ends each call leg and starts the next one itself, and keeps itself in the dialog by rewriting <code>Contact</code>. SDP passes through with only the codecs it won&rsquo;t carry removed, so two phones that both speak G.722 get wideband. <a href="https://github.com/GlomarGadaffi/pocket-dial/blob/main/docs/ARCHITECTURE.md">ARCHITECTURE.md</a> has the full picture.</p>
{svg('callflow',560)}

<h2>When the board does touch the audio</h2>
<p>Some features need a party that can play, record or mix sound. For those the board answers the call itself and terminates the media, PCMU only.</p>
{svg('media',720)}
<p>Heavy outlines mark the legs where the board terminates the media. Everything else stays peer to peer.</p>
'''
h=h.replace('\n<h2 id="quickstart">Quickstart</h2>', how+'\n<h2 id="quickstart">Quickstart</h2>',1)
h=h.replace('<h2 id="hardware">Hardware</h2>\n<table>','<h2 id="hardware">Hardware</h2>\n'+svg('hardware')+'\n<table>',1)
learn=f'''
{svg('learn')}
<p>That is <b>Learn</b> mode: trust on first use. Switch the registrar to <b>Secure</b> and every REGISTER is digest-challenged; an extension with no stored secret cannot register at all.</p>
<p>Which all adds up to one rule:'''
h=h.replace('\n<p>Which all adds up to one rule:',learn,1)
open(p,'w',encoding='utf-8').write(h); print(len(h))
