from pymrtd import ef

# Deserializiranje SOD objekta iz bytov. raw_sod = bytes
sod = ef.SOD.load(raw_sod)

# Sledi preverba sod objekta:
# 1. Preveri če sod objekt vsebuje DSC certifikat.
#    V kodi kličeš metodo .dsCertificates, ki ti vrne seznam DSC certifikatov, lahko pa je ta seznam tudi prazen
# 
# 2. Preverba trust chaina do CSCA:
#    a) SOD vsebuje DSC in če:
#        a) DSC je v bazi, preveriš:
#            - da dsc ni potekel (čas)
#            - da ni revociran
#        b) DSC ni v bazi, preveriš:
#            - da DSC ni v revocirani listi
#            - da DSC ni potekel (čas)
#            - da imaš v bazi CSCA, ki je izdal DSC
#            - da čas do poteka DSC-ja in večji od CSCA-ja
#            - da CSCA ni revociran
#            - da CSCA ni potekel (čas)
#            - da je podpis v DSC certifikatu veljaven s strani CSCA-ja
#    b) SOD ne vsebuje DSC, potem:
#        1) pridobiš DSC iz baze.
#           Kako pridobiš identifikacijo DSC-ja ki je podpisal SOD objekt iz SOD-a in potem DSC iz baze:
#                 1) Pokličeš metodo .signers na SOD objekt. Ta ti vrne seznam objektov tipa asn1crypto.cms.SignerIdentifier.
#                    https://github.com/wbond/asn1crypto/blob/61ae7d7790e460f253c29c5ab7c63b0149f44154/asn1crypto/cms.py#L547-L551
#                 2) Glede na polje ki ga vsebuje SignerIdentifier objekt potem poskušaš poiskat v bazi DSC certifikat.
#
#                    Lih informativno, vsak objekt SignerIdentifier vsebuje ali polje issuer in serisko št. DSC certifikata
#                    ali pa polje subject key identifier DSC certifikata. Zmeraj je samo ena opcija. Issuer polje ni Subject polje v DSC ampak tudi Issuer polje.
#                    Se pravi če SignerIdentifier vsebuje polje Issuer in seriska št., potem iščeš po bazi DSC, ki ima isto serisko št. in istega izdajatelja kot Issuer polje. 
#                    Btw. SOD struktura je implementacija rfc strukture CMS. (to strukturo sem nekako predelal in jo lahko najdeš v pod pki.cms.py modulu)
#                    Kako sem jest zimplementiral v tej strukturi, da najde pravilni certifikat, glede na eno iz med polj v SignerIdentifier si lahko ogledaš tule:
#                    https://github.com/ZeroPass/PassID-Server/blob/master/src/pymrtd/pki/cms.py#L145-L155
#
#                    Še ena informacija glede razreda SignerIdentifier. Implementiran je kot asn1 Choice struktura tako da sam razred potem vsebuje metodo: 
#                        - .chosen - ta ti vrne izbran objekt (ali cms.IssuerAndSerialNumber ali cms.OctetString).
#                          Kateri objekt si dobil lahko preveriš s python-ovo built-in funkcijo -> isinstance
#                        - .name  - ta ti vrne ime polja, ki je izbran, se pravi ali issuer_and_serial_number ali pa subject_key_identifier
#        2) ko si enkrat dobil DSC iz baze narediš isti postopek kot pri postopku, ko je DSC v sodu in v bazi. Se pravi alineja A točka A (DSC je v bazi, preveriš).
#
# 3. Zadnji del je še, da preveriš, da je DSC res izdal sod objekt (preverjanje podpisa).
#    To narediš tako, da na SOD objekt kličeš medodo .verify in ji ne podaš DSC certifikata, če SOD objekt vsebuje DSC.
#    V nasprotnem primeru pa podaš metodi seznam DSC-jev, ki so izdali ta SOD.
#
# Če ti kateri koli korak sfejla, potem ne nadaljuješ naprej ampak vrneš nazaj clientu napako.
# Vse verify metode nič ne vračajo ampak samo mečejo exception, če podpis ni pravilen

sod.verify()


# Nato sledi deserializacij javnega ključa od potnega lista, preverba, da je ta ključ v SOD-u in na kraju preverba podpisov čez challange.
# Primer je narejen za api klic register. Pri ostalih klicih bi mogu vse potrebne parametre in javni ključ že imet v bazi.
# Tako da jih je treba potem samo naložiti iz baze, del kjer se preverja podpis pa ostane isti kot spodaj.

# Deserializacija in preverba DG15 (pub key od potnega lista)
rawDg15 = bytes.fromhex("6F81A230819F300D06092A864886F70D010101050003818D0030818902818100BD8620D45693E1CD8678639F22E9553F09E3AFD87BD26000113CE2798B7A02A2E0AB6B7525D09072109D938D6708167E8FAFAF83F17BFBA36CECCE26058C7ED9AE29516755B19F78CE0E73DA02340B117B8AB2ECA007F1390E93E896016335EB5C1E330B961C03E253D17874F7ABEE8D4962C49FFE578D46954FF23B26F5E5550203010001")
dg15 = ef.DG15.load(rawDg15)
if not sod.ldsSecurityObject.contains(dg15): # preveri, če je dg15 v SOD objektu
    # error return 
    print("dg15 not in sod")

# Če ti je klient poslal še DG14 (signature algorithm), potem ga deserializiraš in preveriš
rawDg14 = bytes.fromhex("6E82016A31820166300D060804007F0007020202020101300F060A04007F0007020203020102010130820142060904007F000702020102308201333081EC06072A8648CE3D02013081E0020101302C06072A8648CE3D0101022100FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF30440420FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC04205AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B0441046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5022100FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC6325510201010342000433137F508550751E730FADA55B9E170CEA098329A1FBD790323AA05BDED901980F170BFAB1C31C43A2DBA3787F7A4A87C3C04B84F79B8800400CC3D2D5632DBC")
dg14 = ef.DG14.load(rawDg14)
aasi = dg14.aaSignatureAlgo # aai je lahko None, če je biu uporabljen RSA za podpis
if not sod.ldsSecurityObject.contains(dg14): # Note: za te konkretne podatke, ta if stavek svejla
    #error return
    print("dg14 not in sod")

#aasi gre na bazo - ce obstaja

# Razsekanje challenga na chunke
# h = hash(challange)
# ccs = [h[0:8], h[8:16], h[16:24], h[24:32]]
       
# Preverjanje podpisov čez chunke
# sigs = [sig1, sig2, sig3, sig4]
# for idx, cc in enumerate(ccs):
#    if not dg15.aaPublicKey.verifySignature(cc, sigs[idx], aai - če je podan):
#        vrzi napako

#aaPublicKey gre na bazo
# Še demonstracija preverbe podpisov čez 1 8 bjtni challange (brez heširanja in rezanja na chunke)
challenge = bytes.fromhex("01 02 03 04 05 06 07 08")
sig = bytes.fromhex("43EDC789988FD9FD5D5A623C20FB7BFB7CC93F69D2B420C7AB5E497375B79EAB8C469F5CB3155908FAE5BC91C3AD8B20A78969D1406D9F80DA4DF8FD19E645681101BAAD6D3A6136A2DDD7A4321159BBFC8254F505E414111F7A3A1995F71D7D5DE5161D8681EF9C8EA7CC8AA843B494F52C0B12B9B2D4797107174FB0AD0BCE")
sig2 = bytes.fromhex("7E460531DDCE3B2180A0D5747EA1F16A33E5B6746C8B9BA752005E4D03ABA49EC48075CA8D7597210216BA64E87D1DBE67892304997CBDC3178B94CA2C2CE6EB0DA58C9F6A959D40070821A8F9EA91F43BEC0488B8ECADAE5D650E0ECC0AA9D40D5F80AB4D1076695C01D4B3CE9F77594159352955D69476A13159729735B378")
sig3 = bytes.fromhex("B2C2A229EE5D08CD7F5AB05DDFC554A02F69D952129D8E1FFB7C406ADAE43237F6E32491EEB48E64C64825F7279FF8B6DE9BBE7358806794B9E119F97A6E51A4967178A048CF902DC9C06E78C1F19AF55A36DB4EAD6306B5D43D34257A1623801AD3C4641174E489881BED6C20C65512CF2C0D0DCFA80B8CADA6BFFB8E5913E9")
sig4 = bytes.fromhex("30CB7FAF340D6E961016C86594D8F30B9750CAFF8E17E8305F74957B1494E53FAEDD5CE59F9268873B2FEE9D0D2D96348711A68800BF6C1E2FB173E876C8F8859A429C56AE494266027559C167AC607859A5F99009AD50CFA73FB659AC6EA33DA7C1E03D2B17A15614AAAFCD0915B7EC5AB7E987C4B01B3A58144266126D1D4B")
sig5 = bytes.fromhex("B7E3CBDC7BBC850CBD67AE8417498E7B1BAC90B9F4DABCCC48FB84CE73133A3EF44793D01DBF2B18E0C7913A18A3E75DBF5C7AFCD4EB905E87F6DD2A58144F836D16F43D4FC44F2D68A052FBB3EB4FEA4AF112C63EB4A65B3804CD0327F8D6C54C43E6776CCB38FA7A78DD41C2928CA1F8A638A73C4D467203BA4CC066C07DFC")
sig6 = bytes.fromhex("0A20A09A25C38223E7CE864EEDEC412E95BE8EC7F9560ABB53B0AFF2B8CCF8C9CED4706C9074CF6D2EBB891BF3D479941B8A5A994605E9B0E0CA8EEBABB12A5AA4926AA2EABF97C28F37376A7F89BC189BEAFD2F7BCA055EDB992369A50B1E2B2E51062789A191635E1001DD26F75ED8DB0B8D88222FFC8F2771C969130E0A09")
sig7 = bytes.fromhex("09C83665E0923C517B17FA82EFFAD28BFCCD7368B719E8C3D1C537B06C2F21AB5D35DD0805EB4922A337A80C8DDDCE3266F6FAB43F31ADA1C73F76F5A9397311C3CA19403DFE5595EC007820E27240FEC478C475910DB28B98415456B0AA0DDA13921BF0D3CB8346A863D07C84F06580EF11B52DEF90EF4CCD0B2D619A518FB9")

assert dg15.aaPublicKey.verifySignature(challenge, sig)
assert dg15.aaPublicKey.verifySignature(challenge, sig2)
assert dg15.aaPublicKey.verifySignature(challenge, sig3)
assert dg15.aaPublicKey.verifySignature(challenge, sig4)
assert dg15.aaPublicKey.verifySignature(challenge, sig5)
assert dg15.aaPublicKey.verifySignature(challenge, sig6)
assert dg15.aaPublicKey.verifySignature(challenge, sig7)
