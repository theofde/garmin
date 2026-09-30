# Garmin MCP multi-client gateway

Ce service transforme `Taxuspt/garmin_mcp` en intégration multi-utilisateur pour PolyPacer.

- un tenant PolyPacer = un répertoire de tokens Garmin séparé sous `/data/users/<sha256>/tokens`
- les identifiants Garmin ne sont jamais enregistrés; ils servent uniquement à créer les tokens OAuth
- MFA est géré par un challenge éphémère de 10 minutes
- `/v1/activities` sert la synchronisation PolyPacer
- `/mcp` expose le MCP Garmin complet en `streamable-http`; le gateway démarre un processus `garmin-mcp` isolé par tenant
- chaque requête doit inclure `Authorization: Bearer <GARMIN_MCP_GATEWAY_SECRET>` et `X-Tenant-Id: <id utilisateur>`

## Déploiement

Le service doit tourner sur un hébergeur Docker persistant (Render, Railway, Fly.io, VPS, etc.), pas dans une Netlify Function.

Variables:

```env
GARMIN_MCP_GATEWAY_SECRET=une-cle-longue-et-aleatoire
GARMIN_DATA_DIR=/data
PORT=8080
```

Monte `/data` sur un volume persistant. Garde une seule réplique du gateway, ou configure des sessions persistantes/sticky pour que le challenge MFA reste sur la même instance pendant ses 10 minutes de validité. Dans Netlify, configure ensuite exactement le même secret et l'URL publique:

```env
GARMIN_MCP_GATEWAY_URL=https://garmin-mcp.example.com
GARMIN_MCP_GATEWAY_SECRET=une-cle-longue-et-aleatoire
```

Test:

```bash
curl https://garmin-mcp.example.com/healthz
```

Important: Garmin Connect n'est pas une API publique stable. Cette intégration s'appuie sur `python-garminconnect` via le projet `Taxuspt/garmin_mcp`; une évolution de Garmin peut nécessiter une mise à jour du gateway.
