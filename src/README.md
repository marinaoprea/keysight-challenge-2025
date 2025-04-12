### Overwiew

Implementarea acopera toate functionalitatile din enunt;

- Am facut nod pentru filtrarea pachetelor IPv4, care face si statistici pentru
pachete de tip UDP si TCP; 
- Am facut nod pentru modificare adreselor destinatiei IP, nodurile isi trimit
un vector de `PacketData`;
- `PacketData` pastreaza formatul pcap, pastreaza header-ul si datele separat;
- Am printat pachetele finale tot intr-un fisier pcap, am incercat sa le
trimitem pe socket, dar nu functionaza.

Bonus:
- Filtrarea am facut-o cu parallel_for si am mapat cu 0 si 1 pachetele de tip
IPv4, iar dupa am aplicat parallel_reduce ca sa aflam numarul de pachete
- Analog pentru UDP si TCP
- Am folosit C++ arrays