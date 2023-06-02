# **FireArmor**
**[DP CYBER] Master Projet - Fire Armor**

**Exploit AI power to detect malicious code injection**

Fire Armor provides realtime observability and runtime enforcement on micro-services executed on K8S cluster.When using K8S environment, an attacker may discover and exploit a micro-service vulnerability. Such vulnerability can  next  be  used  to  laterilize  on  other  micro-services  running  on  the  same  K8S,  or  to  attack  any  other  services running out of K8S but reachable from the vulnerable micro-service. Fire Armor detects and reacts to events such as :

- Process execution event
- System call activity
- Network and file access

Fire  Armor  trains  an  AI  model  to  learn  the  micro-service  normal  behavior,  and  next  uses  this  model  to  detect abnormal activities and react.

Fire Armor aims to work with different technologies :
- Rust language
- Kubernetes
- cilium
- OpenSearch

BERNET Matthis - COUSSEAU Mathias - MILLET Hugo - SORROCHE Loïc
